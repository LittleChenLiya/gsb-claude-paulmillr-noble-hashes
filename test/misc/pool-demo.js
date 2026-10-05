// Local, dependency-free demo of HashPool. Run from the repo root with Node >= 22.6 (or 20.19+
// with --experimental-strip-types):
//
//   node test/misc/pool-demo.js
//
// It exercises the acceptance flow on a capacity-1 pool: the first tenant hashes 'abc', returns
// the lease (old state destroyed, fresh empty instance created), and the second tenant hashes the
// empty string and must receive the canonical empty SHA-256 digest — proving no residue leaks
// across rentals. Also prints the cancellation and close lifecycle.
import { HashPool, PoolClosedError } from '../../src/hash-pool.ts';
import { sha256 } from '../../src/sha2.ts';
import { utf8ToBytes } from '../../src/utils.ts';

const hex = (bytes) => Buffer.from(bytes).toString('hex');
const SHA256_EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';

const pool = new HashPool(sha256.create, { capacity: 1 });

// Tenant 1: hash 'abc', then return.
const first = await pool.acquire();
const abc = first.hash.update(utf8ToBytes('abc')).digest();
console.log('tenant 1, sha256("abc")   =', hex(abc));
if (hex(abc) !== SHA256_ABC) throw new Error('unexpected abc digest');
first.release();

// Tenant 2: must get a pristine instance — empty string yields the empty-string digest.
const second = await pool.acquire();
const empty = second.hash.update(utf8ToBytes('')).digest();
console.log('tenant 2, sha256("")      =', hex(empty));
if (hex(empty) !== SHA256_EMPTY) throw new Error('message residue leaked across rentals!');
second.release();

// Waiting tenant cancels: its permit must remain available.
const held = await pool.acquire();
const ac = new AbortController();
const cancelled = pool.acquire(ac.signal).catch((e) => e);
ac.abort();
const cancelErr = await cancelled;
console.log('cancelled waiter rejects  =', cancelErr.name);
held.release();
(await pool.acquire()).release();
console.log('permit reusable after cancel: ok, pool.size =', pool.size);

// Close wakes waiters, processes the in-flight return, then refuses to lend.
const inFlight = await pool.acquire();
const waiterErr = pool.acquire().catch((e) => e);
let closed = false;
const closing = pool.close().then(() => (closed = true));
console.log(
  'closed while 1 in flight  =',
  (await waiterErr) instanceof PoolClosedError,
  '(waiter woken)'
);
inFlight.release(); // in-flight return during shutdown
await closing;
console.log('close() settled after return =', closed);
try {
  await pool.acquire();
  throw new Error('acquire after close must fail');
} catch (e) {
  console.log('acquire after close       =', e.name);
}

console.log('pool demo OK');
