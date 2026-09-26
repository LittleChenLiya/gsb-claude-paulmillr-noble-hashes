/**
 * Terminal example for MultiHasher and updateFromAsyncIterable.
 * Run: node examples/multihash.ts
 * Prints success digests for chunked input and cleanup counts after cancellation.
 */
import { MultiHasher, updateFromAsyncIterable } from '../src/multihash.ts';
import { sha256, sha512 } from '../src/sha2.ts';
import { bytesToHex, utf8ToBytes, type Hash } from '../src/utils.ts';

// 1. Success path: 'abc' fed as 'a' + 'bc' into SHA-256 and SHA-512 at once.
const multi = new MultiHasher([
  ['sha256', () => sha256.create()],
  ['sha512', () => sha512.create()],
]);
multi.update(utf8ToBytes('a')).update(utf8ToBytes('bc'));
for (const [name, digest] of multi.digest()) console.log(`${name}: ${bytesToHex(digest)}`);
multi.destroy();

// 2. Cancellation path: abort mid-stream, then report cleanup counts.
let destroyCalls = 0;
class CountingHash implements Hash<CountingHash> {
  readonly blockLen = 8;
  readonly outputLen = 4;
  readonly canXOF = false;
  finished = false;
  destroyed = false;
  update(): this {
    return this;
  }
  digestInto(buf: Uint8Array): void {
    this.finished = true;
    buf.fill(0);
  }
  digest(): Uint8Array {
    return new Uint8Array(this.outputLen);
  }
  destroy(): void {
    destroyCalls++;
    this.destroyed = true;
  }
  _cloneInto(to?: CountingHash): CountingHash {
    return to === undefined ? new CountingHash() : to;
  }
  clone(): CountingHash {
    return this._cloneInto();
  }
}

const ac = new AbortController();
let returnCalls = 0;
async function* stream() {
  yield utf8ToBytes('chunk-1');
  ac.abort(new Error('cancelled by user'));
  yield utf8ToBytes('chunk-2');
}
const it = stream();
const origReturn = it.return!.bind(it);
it.return = async (...args: any[]) => {
  returnCalls++;
  return origReturn(...args);
};

const cancellable = new MultiHasher([
  ['counter-a', () => new CountingHash()],
  ['counter-b', () => new CountingHash()],
]);
try {
  await updateFromAsyncIterable(cancellable, it, { signal: ac.signal });
  console.log('unexpected: stream completed');
} catch (err) {
  console.log('cancelled:', (err as Error).message);
}
console.log(`iterator return() calls: ${returnCalls}`);
console.log(`inner destroy() calls: ${destroyCalls} (expected 2)`);
// Idempotency check: a second cleanup pass must not destroy again.
cancellable.destroy();
console.log(`inner destroy() calls after re-cleanup: ${destroyCalls} (expected 2)`);
