import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, throws } from 'node:assert';
import { MultiHasher, createMultiHasher, hashStream } from '../src/multihash.ts';
import { sha256, sha512 } from '../src/sha2.ts';
import { bytesToHex, utf8ToBytes } from '../src/utils.ts';

const ABC = utf8ToBytes('abc');
const CHUNKS_ABC = [utf8ToBytes('a'), utf8ToBytes('bc')];

const sha2Specs = () => [
  { name: 'sha256', create: () => sha256.create() },
  { name: 'sha512', create: () => sha512.create() },
];

// Fake hash with counters, used to verify cleanup happens exactly once.
function fakeHashFactory(counters, opts = {}) {
  const shared = opts.sharedDigest ? new Uint8Array([1, 2, 3, 4]) : undefined;
  return {
    create() {
      const state = {
        created: 1,
        destroyed: 0,
        cloned: 0,
        bytes: [],
        digests: 0,
      };
      counters.push(state);
      const hash = {
        blockLen: 4,
        outputLen: 4,
        canXOF: false,
        update(buf) {
          state.bytes.push(...buf);
          return hash;
        },
        digest() {
          state.digests++;
          return shared ? shared : Uint8Array.from(state.bytes.slice(0, 4));
        },
        digestInto() {},
        destroy() {
          state.destroyed++;
        },
        clone() {
          state.cloned++;
          const inner = fakeHashFactory(counters, opts).create();
          inner.update(Uint8Array.from(state.bytes));
          return inner;
        },
        _cloneInto() {
          return hash;
        },
      };
      return hash;
    },
  };
}

// Async iterable with close/error tracking.
function trackedStream(chunks, opts = {}) {
  const state = { returned: 0, yielded: 0 };
  const iterable = {
    [Symbol.asyncIterator]() {
      let index = 0;
      return {
        async next() {
          if (opts.throwAt === index) throw new Error('read boom');
          if (index >= chunks.length) return { done: true, value: undefined };
          state.yielded++;
          return { done: false, value: chunks[index++] };
        },
        async return() {
          state.returned++;
          return { done: true, value: undefined };
        },
      };
    },
  };
  return { iterable, state };
}

describe('multihash', () => {
  it('matches standalone hashes for chunked input', () => {
    const mh = new MultiHasher(sha2Specs());
    mh.update(CHUNKS_ABC[0]).update(CHUNKS_ABC[1]);
    const out = mh.digest();
    eql(out.sha256, sha256(ABC));
    eql(out.sha512, sha512(ABC));
    eql(bytesToHex(out.sha256), bytesToHex(sha256(ABC)));
    eql(bytesToHex(out.sha512), bytesToHex(sha512(ABC)));
  });
  it('names keep insertion order, are frozen and unique', () => {
    const mh = new MultiHasher(sha2Specs());
    eql([...mh.names], ['sha256', 'sha512']);
    throws(() => mh.names.push('x'), TypeError);
    throws(
      () =>
        new MultiHasher([
          { name: 'sha256', create: () => sha256.create() },
          { name: 'sha256', create: () => sha512.create() },
        ]),
      /duplicate hash name/
    );
    throws(() => new MultiHasher([]), /at least one/);
    throws(() => new MultiHasher([{ name: '', create: () => sha256.create() }]), TypeError);
    throws(() => new MultiHasher([{ name: 'x' }]), TypeError);
    throws(() => new MultiHasher(null), TypeError);
  });
  it('digest returns independent copies', () => {
    const counters = [];
    const mh = new MultiHasher([
      { name: 'fake', create: fakeHashFactory(counters, { sharedDigest: true }).create },
    ]);
    mh.update(ABC);
    const clone = mh.clone();
    const out = mh.digest();
    // The fake returns the same shared buffer every time; MultiHasher must copy it.
    out.fake[0] = 0xff;
    const again = clone.digest();
    eql(again.fake, Uint8Array.from([1, 2, 3, 4]));
    eql(out.fake === again.fake, false);
  });
  it('rejects update/digest after digest and after destroy', () => {
    const mh = new MultiHasher(sha2Specs());
    mh.update(ABC);
    mh.digest();
    throws(() => mh.update(ABC), /digest\(\) was already called/);
    throws(() => mh.digest(), /digest\(\) was already called/);
    const mh2 = new MultiHasher(sha2Specs());
    mh2.destroy();
    throws(() => mh2.update(ABC), /destroyed/);
    throws(() => mh2.digest(), /destroyed/);
    throws(() => mh2.clone(), /destroyed/);
  });
  it('clone is independent: different suffixes give different digests', () => {
    const mh = new MultiHasher(sha2Specs());
    mh.update(CHUNKS_ABC[0]);
    const cloned = mh.clone();
    mh.update(utf8ToBytes('bc'));
    cloned.update(utf8ToBytes('XYZ'));
    const a = mh.digest();
    const b = cloned.digest();
    eql(a.sha256, sha256(ABC));
    eql(a.sha512, sha512(ABC));
    eql(b.sha256, sha256(utf8ToBytes('aXYZ')));
    eql(b.sha512, sha512(utf8ToBytes('aXYZ')));
    // Mutating one clone must not leak into the other.
    eql(bytesToHex(a.sha256) === bytesToHex(b.sha256), false);
  });
  it('failed construction destroys already-created hashes exactly once', () => {
    const counters = [];
    const factory = fakeHashFactory(counters);
    throws(
      () =>
        new MultiHasher([
          { name: 'ok1', create: factory.create },
          { name: 'ok2', create: factory.create },
          {
            name: 'boom',
            create: () => {
              throw new Error('init boom');
            },
          },
        ]),
      /init boom/
    );
    eql(counters.length, 2);
    for (const c of counters) eql(c.destroyed, 1);
    // Re-check cleanup: nothing half-usable remains, no extra destroys on GC/second pass.
    for (const c of counters) eql(c.destroyed, 1);
  });
  it('destroy is idempotent and destroys inner hashes exactly once', () => {
    const counters = [];
    const factory = fakeHashFactory(counters);
    const mh = new MultiHasher([
      { name: 'a', create: factory.create },
      { name: 'b', create: factory.create },
    ]);
    mh.update(ABC);
    mh.destroy();
    mh.destroy();
    mh.destroy();
    eql(counters.length, 2);
    for (const c of counters) eql(c.destroyed, 1);
  });
  it('createMultiHasher factory works', () => {
    const mh = createMultiHasher(sha2Specs());
    mh.update(ABC);
    eql(mh.digest().sha256, sha256(ABC));
  });
  it('rejects non-Uint8Array chunks in update', () => {
    const mh = new MultiHasher(sha2Specs());
    throws(() => mh.update('abc'), TypeError);
    throws(() => mh.update([1, 2, 3]), TypeError);
    mh.destroy();
  });
  describe('hashStream', () => {
    it('hashes a/bc chunks like standalone hashes', async () => {
      const { iterable, state } = trackedStream(CHUNKS_ABC);
      const mh = new MultiHasher(sha2Specs());
      const out = await hashStream(iterable, mh);
      eql(out.sha256, sha256(ABC));
      eql(out.sha512, sha512(ABC));
      eql(state.yielded, 2);
    });
    it('handles empty stream', async () => {
      const { iterable } = trackedStream([]);
      const out = await hashStream(iterable, new MultiHasher(sha2Specs()));
      eql(out.sha256, sha256(new Uint8Array()));
      eql(out.sha512, sha512(new Uint8Array()));
    });
    it('accepts sync iterables', async () => {
      const out = await hashStream(CHUNKS_ABC, new MultiHasher(sha2Specs()));
      eql(out.sha256, sha256(ABC));
    });
    it('cleans up exactly once on read error', async () => {
      const counters = [];
      const factory = fakeHashFactory(counters);
      const { iterable, state } = trackedStream([utf8ToBytes('a')], { throwAt: 1 });
      const mh = new MultiHasher([
        { name: 'a', create: factory.create },
        { name: 'b', create: factory.create },
      ]);
      await rejects(() => hashStream(iterable, mh), /read boom/);
      eql(state.returned, 1);
      for (const c of counters) eql(c.destroyed, 1);
      // Second cleanup check: still exactly one destroy per hash.
      mh.destroy();
      for (const c of counters) eql(c.destroyed, 1);
    });
    it('cleans up exactly once on invalid chunk', async () => {
      const counters = [];
      const factory = fakeHashFactory(counters);
      const { iterable, state } = trackedStream([utf8ToBytes('a'), 'not-bytes', [1, 2, 3]]);
      const mh = new MultiHasher([
        { name: 'a', create: factory.create },
        { name: 'b', create: factory.create },
      ]);
      await rejects(() => hashStream(iterable, mh), TypeError);
      eql(state.returned, 1);
      for (const c of counters) eql(c.destroyed, 1);
      mh.destroy();
      for (const c of counters) eql(c.destroyed, 1);
    });
    it('cleans up exactly once on abort', async () => {
      const counters = [];
      const factory = fakeHashFactory(counters);
      const controller = new AbortController();
      const { iterable, state } = trackedStream(CHUNKS_ABC);
      const mh = new MultiHasher([
        { name: 'a', create: factory.create },
        { name: 'b', create: factory.create },
      ]);
      controller.abort();
      await rejects(() => hashStream(iterable, mh, { signal: controller.signal }));
      eql(state.returned, 1);
      for (const c of counters) eql(c.destroyed, 1);
      mh.destroy();
      for (const c of counters) eql(c.destroyed, 1);
    });
    it('rejects invalid arguments', async () => {
      await rejects(() => hashStream(null, new MultiHasher(sha2Specs())), TypeError);
      await rejects(() => hashStream(42, new MultiHasher(sha2Specs())), TypeError);
      await rejects(() => hashStream(trackedStream([]).iterable, {}), TypeError);
    });
  });
});
