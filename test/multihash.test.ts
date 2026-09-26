import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, throws } from 'node:assert';
import { MultiHasher, updateFromAsyncIterable } from '../src/multihash.ts';
import { sha256, sha512 } from '../src/sha2.ts';
import { bytesToHex, utf8ToBytes, type Hash } from '../src/utils.ts';

// Counting fake hash: tracks destroy calls to verify exactly-once cleanup.
class FakeHash implements Hash<FakeHash> {
  static destroyCalls = 0;
  static reset(): void {
    FakeHash.destroyCalls = 0;
  }
  readonly blockLen = 8;
  readonly outputLen = 4;
  readonly canXOF = false;
  finished = false;
  destroyed = false;
  private bytes: number[] = [];
  update(buf: Uint8Array): this {
    if (this.destroyed) throw new Error('hash was destroyed');
    if (this.finished) throw new Error('digest() was already called');
    for (const b of buf) this.bytes.push(b);
    return this;
  }
  digestInto(buf: Uint8Array): void {
    if (this.destroyed) throw new Error('hash was destroyed');
    if (this.finished) throw new Error('digest() was already called');
    this.finished = true;
    let sum = 0;
    for (const b of this.bytes) sum = (sum + b) >>> 0;
    buf.set([sum & 0xff, (sum >>> 8) & 0xff, (sum >>> 16) & 0xff, this.bytes.length & 0xff]);
  }
  digest(): Uint8Array {
    const out = new Uint8Array(this.outputLen);
    this.digestInto(out);
    return out;
  }
  destroy(): void {
    FakeHash.destroyCalls++;
    this.destroyed = true;
    this.bytes = [];
  }
  _cloneInto(to?: FakeHash): FakeHash {
    const clone = to === undefined ? new FakeHash() : to;
    clone.bytes = this.bytes.slice();
    clone.finished = this.finished;
    return clone;
  }
  clone(): FakeHash {
    return this._cloneInto();
  }
}

const shaEntries = (): [string, () => Hash<any>][] => [
  ['sha256', () => sha256.create()],
  ['sha512', () => sha512.create()],
];

describe('multihash', () => {
  it('chunked a/bc equals standalone sha256 and sha512', () => {
    const multi = new MultiHasher(shaEntries());
    multi.update(utf8ToBytes('a')).update(utf8ToBytes('bc'));
    const digests = multi.digest();
    eql(digests.get('sha256'), sha256(utf8ToBytes('abc')));
    eql(digests.get('sha512'), sha512(utf8ToBytes('abc')));
    multi.destroy();
  });
  it('names keep insertion order and reject duplicates', () => {
    const multi = new MultiHasher(shaEntries());
    eql(multi.names, ['sha256', 'sha512']);
    const reversed = new MultiHasher([
      ['sha512', () => sha512.create()],
      ['sha256', () => sha256.create()],
    ]);
    eql(reversed.names, ['sha512', 'sha256']);
    eql(reversed.digest().get('sha256'), sha256(new Uint8Array(0)));
    throws(() => new MultiHasher([...shaEntries(), ['sha256', () => sha256.create()]]));
    throws(() => new MultiHasher([]));
    throws(() => new MultiHasher([['', () => sha256.create()]]));
    multi.destroy();
    reversed.destroy();
  });
  it('digest returns independent copies', () => {
    const multi = new MultiHasher(shaEntries());
    multi.update(utf8ToBytes('abc'));
    const first = multi.digest();
    const second = multi.digest();
    eql(first.get('sha256'), second.get('sha256'));
    // Different backing buffers: mutating one copy must not affect the other.
    first.get('sha256')!.fill(0);
    eql(second.get('sha256'), sha256(utf8ToBytes('abc')));
    multi.destroy();
  });
  it('update after digest is rejected', () => {
    const multi = new MultiHasher(shaEntries());
    multi.update(utf8ToBytes('abc'));
    multi.digest();
    throws(() => multi.update(utf8ToBytes('x')), /digest\(\) was already called/);
    throws(() => multi.clone());
    multi.destroy();
    throws(() => multi.update(utf8ToBytes('x')), /multihash was destroyed/);
    throws(() => multi.digest(), /multihash was destroyed/);
  });
  it('clone produces independent state', () => {
    const base = new MultiHasher(shaEntries());
    base.update(utf8ToBytes('abc'));
    const fork = base.clone();
    eql(fork.names, ['sha256', 'sha512']);
    base.update(utf8ToBytes('-left'));
    fork.update(utf8ToBytes('-right'));
    eql(base.digest().get('sha256'), sha256(utf8ToBytes('abc-left')));
    eql(fork.digest().get('sha256'), sha256(utf8ToBytes('abc-right')));
    eql(base.digest().get('sha512'), sha512(utf8ToBytes('abc-left')));
    eql(fork.digest().get('sha512'), sha512(utf8ToBytes('abc-right')));
    base.destroy();
    fork.destroy();
  });
  it('init failure destroys already-created hashes and leaves no usable instance', () => {
    FakeHash.reset();
    throws(
      () =>
        new MultiHasher([
          ['fake-a', () => new FakeHash()],
          ['fake-b', () => new FakeHash()],
          [
            'broken',
            () => {
              throw new Error('init boom');
            },
          ],
        ]),
      /init boom/
    );
    // Both created fakes were destroyed exactly once during cleanup.
    eql(FakeHash.destroyCalls, 2);
  });
  it('destroy is idempotent: inner hashes destroyed exactly once', () => {
    FakeHash.reset();
    const multi = new MultiHasher([
      ['fake-a', () => new FakeHash()],
      ['fake-b', () => new FakeHash()],
    ]);
    multi.update(utf8ToBytes('abc'));
    multi.destroy();
    eql(FakeHash.destroyCalls, 2);
    // Second cleanup pass must not destroy again.
    multi.destroy();
    eql(FakeHash.destroyCalls, 2);
  });
  it('async adapter: chunked stream matches standalone', async () => {
    async function* stream() {
      yield utf8ToBytes('a');
      yield utf8ToBytes('bc');
    }
    const multi = new MultiHasher(shaEntries());
    const res = await updateFromAsyncIterable(multi, stream());
    eql(res, multi);
    eql(multi.digest().get('sha256'), sha256(utf8ToBytes('abc')));
    eql(multi.digest().get('sha512'), sha512(utf8ToBytes('abc')));
    multi.destroy();
  });
  it('async adapter: empty stream', async () => {
    async function* stream() {}
    const multi = new MultiHasher(shaEntries());
    await updateFromAsyncIterable(multi, stream());
    eql(multi.digest().get('sha256'), sha256(new Uint8Array(0)));
    multi.destroy();
  });
  it('async adapter: invalid chunk closes iterator and destroys state once', async () => {
    FakeHash.reset();
    let returnCalls = 0;
    const chunks: any[] = [utf8ToBytes('abc'), [1, 2, 3]];
    const iterator: AsyncIterator<any> = {
      next: async () => {
        const value = chunks.shift();
        return value === undefined ? { done: true, value: undefined } : { done: false, value };
      },
      return: async () => {
        returnCalls++;
        return { done: true, value: undefined };
      },
    };
    const multi = new MultiHasher([
      ['fake-a', () => new FakeHash()],
      ['fake-b', () => new FakeHash()],
    ]);
    await rejects(() => updateFromAsyncIterable(multi, iterator), /expected Uint8Array/);
    eql(returnCalls, 1);
    eql(FakeHash.destroyCalls, 2);
    // Re-running cleanup must be a no-op.
    multi.destroy();
    eql(FakeHash.destroyCalls, 2);
  });
  it('async adapter: read error closes iterator and destroys state once', async () => {
    FakeHash.reset();
    let returnCalls = 0;
    async function* stream() {
      yield utf8ToBytes('abc');
      throw new Error('read boom');
    }
    const it = stream();
    const origReturn = it.return!.bind(it);
    it.return = async (...args: any[]) => {
      returnCalls++;
      return origReturn(...args);
    };
    const multi = new MultiHasher([
      ['fake-a', () => new FakeHash()],
      ['fake-b', () => new FakeHash()],
    ]);
    await rejects(() => updateFromAsyncIterable(multi, it), /read boom/);
    eql(returnCalls, 1);
    eql(FakeHash.destroyCalls, 2);
    multi.destroy();
    eql(FakeHash.destroyCalls, 2);
  });
  it('async adapter: abort cancels and destroys state once', async () => {
    FakeHash.reset();
    let returnCalls = 0;
    const ac = new AbortController();
    async function* stream() {
      yield utf8ToBytes('abc');
      ac.abort(new Error('cancelled by user'));
      yield utf8ToBytes('def');
    }
    const it = stream();
    const origReturn = it.return!.bind(it);
    it.return = async (...args: any[]) => {
      returnCalls++;
      return origReturn(...args);
    };
    const multi = new MultiHasher([
      ['fake-a', () => new FakeHash()],
      ['fake-b', () => new FakeHash()],
    ]);
    await rejects(
      () => updateFromAsyncIterable(multi, it, { signal: ac.signal }),
      /cancelled by user/
    );
    eql(returnCalls, 1);
    eql(FakeHash.destroyCalls, 2);
    multi.destroy();
    eql(FakeHash.destroyCalls, 2);
  });
  it('async adapter: validates arguments', async () => {
    const multi = new MultiHasher(shaEntries());
    await rejects(() => updateFromAsyncIterable(null as any, [] as any), TypeError);
    await rejects(() => updateFromAsyncIterable(multi, 42 as any), TypeError);
    multi.destroy();
  });
  it('known vectors', () => {
    const multi = new MultiHasher(shaEntries());
    multi.update(utf8ToBytes('abc'));
    const digests = multi.digest();
    eql(
      bytesToHex(digests.get('sha256')!),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
    eql(
      bytesToHex(digests.get('sha512')!),
      'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a' +
        '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f'
    );
    multi.destroy();
  });
});
