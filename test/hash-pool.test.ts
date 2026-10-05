import { beforeEach, describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, strictEqual as eq, throws } from 'node:assert';
import { pathToFileURL } from 'node:url';
import { sha256 } from '../src/sha2.ts';
import { utf8ToBytes } from '../src/utils.ts';
import { HashPool, PoolClosedError } from '../src/hash-pool.ts';

// Deterministic scheduling helper: flush the microtask queue N times without relying on wall
// clocks. acquire() hands off via microtasks only, so a fixed number of flushes makes ordering of
// waiters / aborts / close-wakeups fully controllable and repeatable.
const flush = (n = 1): Promise<void> =>
  Array.from({ length: n }, () => Promise.resolve()).reduce(
    (p: Promise<unknown>, tick) => p.then(() => tick),
    Promise.resolve()
  ) as Promise<void>;

// Minimal controllable cloneable hash stand-in: accumulates bytes as a plain string and records
// how many instances were created / how many times destroy() ran per instance.
let seq = 0;
class FakeHash {
  readonly id: number;
  state = '';
  destroyed = false;
  destroyCalls = 0;
  readonly blockLen = 1;
  readonly outputLen = 1;
  readonly canXOF = false;
  constructor() {
    this.id = seq++;
    FakeHash.created.push(this);
  }
  update(data: Uint8Array): this {
    if (this.destroyed) throw new Error('use after destroy');
    this.state += String.fromCharCode(...data);
    return this;
  }
  digest(): Uint8Array {
    this.destroy();
    return new Uint8Array([this.state.length & 0xff]);
  }
  digestInto(out: Uint8Array): void {
    out[0] = this.state.length & 0xff;
    this.destroy();
  }
  clone(): FakeHash {
    const c = new FakeHash();
    c.state = this.state;
    return c;
  }
  _cloneInto(to?: FakeHash): FakeHash {
    const target = to || new FakeHash();
    target.state = this.state;
    return target;
  }
  destroy(): void {
    this.destroyCalls++;
    this.destroyed = true;
    this.state = '';
  }
  static created: FakeHash[] = [];
  static reset(): void {
    FakeHash.created = [];
    seq = 0;
  }
}

describe('hash pool', () => {
  beforeEach(() => FakeHash.reset());

  it('capacity 1: release destroys old state, next tenant gets an empty instance', async () => {
    // Acceptance case with the real sha256: 'abc' then empty-string digest.
    const pool = new HashPool(sha256.create, { capacity: 1 });
    const a = await pool.acquire();
    eql(
      a.hash.update(utf8ToBytes('abc')).digest(),
      sha256(utf8ToBytes('abc')),
      'first tenant hashes abc'
    );
    a.release();

    const b = await pool.acquire();
    eql(
      b.hash.update(utf8ToBytes('')).digest(),
      sha256(utf8ToBytes('')),
      'second tenant gets the empty-string digest, no abc residue'
    );
    b.release();
    eq(pool.size, 1, 'one replacement instance slots in for the destroyed one');
    await pool.close();
  });

  it('return creates a fresh empty instance and destroys the used one exactly once', async () => {
    const pool = new HashPool(() => new FakeHash(), { capacity: 1 });
    const lease = await pool.acquire();
    const used = lease.hash as FakeHash;
    used.update(utf8ToBytes('secret'));
    lease.release();
    eq(used.destroyed, true, 'used instance is destroyed');
    eq(used.destroyCalls, 1, 'destroy runs exactly once on return');
    eq(used.state, '', 'no message residue survives');
    eq(FakeHash.created.length, 2, 'a new empty instance replaced the destroyed one');

    const next = await pool.acquire();
    const fresh = next.hash as FakeHash;
    eq(fresh.state, '', 'replacement starts empty');
    eq(fresh.id, 1);
    next.release();
    eq(fresh.destroyCalls, 1);
    await pool.close();
  });

  it('capacity bounds simultaneous leases and wakeups are FIFO', async () => {
    const pool = new HashPool(() => new FakeHash(), { capacity: 2 });
    const a = await pool.acquire();
    const b = await pool.acquire();
    eq(pool.size, 2);

    let third: Awaited<ReturnType<HashPool<FakeHash>['acquire']>> | undefined;
    let fourth: typeof third;
    const p3 = pool.acquire().then((l) => (third = l));
    const p4 = pool.acquire().then((l) => (fourth = l));
    await flush();
    eq(third, undefined);
    eq(fourth, undefined);
    eq(pool.pending, 2);

    a.release(); // factory replacement handed straight to the head waiter
    await flush();
    eq(third && (third.hash as FakeHash).id, 2, 'FIFO: waiter #1 woken first');
    eq(fourth, undefined);

    b.release();
    await flush();
    eq(fourth && (fourth.hash as FakeHash).id, 3, 'FIFO: waiter #2 woken next');
    await p3;
    await p4;
    third!.release();
    fourth!.release();
    await pool.close();
  });

  it('cancelled wait consumes no permit and leaves capacity for the next tenant', async () => {
    const pool = new HashPool(() => new FakeHash(), { capacity: 1 });
    const held = await pool.acquire();

    const ac = new AbortController();
    let err: unknown;
    const waiting = pool.acquire(ac.signal).catch((e) => (err = e));
    await flush();
    eq(pool.pending, 1);

    ac.abort();
    await waiting;
    eq((err as Error).name, 'AbortError');
    eq(pool.pending, 0, 'cancelled waiter is removed from the queue');
    eq(pool.size, 1, 'no instance created / permit consumed by the cancelled wait');

    held.release();
    const next = await pool.acquire(); // resolves immediately: permit fully intact
    eq((next.hash as FakeHash).id, 1, 'fresh replacement instance lent out');
    next.release();
    await pool.close();
  });

  it('pre-aborted signal rejects without touching the pool', async () => {
    const pool = new HashPool(() => new FakeHash(), { capacity: 1 });
    const held = await pool.acquire();
    await rejects(pool.acquire(AbortSignal.abort()), /aborted/i);
    eq(pool.pending, 0);
    held.release();
    await pool.close();
  });

  it('abort reason is propagated verbatim', async () => {
    const pool = new HashPool(() => new FakeHash(), { capacity: 1 });
    const held = await pool.acquire();
    const custom = new Error('nope');
    const ac = new AbortController();
    const p = rejects(pool.acquire(ac.signal), (e: Error) => e === custom);
    await flush();
    ac.abort(custom);
    await p;
    held.release();
    await pool.close();
  });

  it('double release is explicitly rejected and does not destroy twice', async () => {
    const pool = new HashPool(() => new FakeHash(), { capacity: 1 });
    const lease = await pool.acquire();
    const used = lease.hash as FakeHash;
    lease.release();
    throws(() => lease.release(), /twice/);
    eq(used.destroyCalls, 1, 'rejected repeat return never reaches destroy()');
    await pool.close();
  });

  it('releasing an instance the pool never lent is rejected', async () => {
    const pool = new HashPool(() => new FakeHash(), { capacity: 1 });
    const stranger = new FakeHash();
    const giveBack = (pool as unknown as { giveBack(h: FakeHash): void }).giveBack.bind(pool);
    throws(() => giveBack(stranger), /already released|does not belong/);
    eq(stranger.destroyCalls, 0, 'foreign instance is never destroyed by the pool');
    await pool.close();
  });

  it('close wakes all waiters with PoolClosedError and never lends again', async () => {
    const pool = new HashPool(() => new FakeHash(), { capacity: 1 });
    const held = await pool.acquire();
    const errs: unknown[] = [];
    const w1 = pool.acquire().catch((e) => errs.push(e));
    const w2 = pool.acquire().catch((e) => errs.push(e));
    await flush();
    eq(pool.pending, 2);

    let closed = false;
    const closing = pool.close().then(() => (closed = true));
    await Promise.all([w1, w2]);
    eq(errs.length, 2);
    eq(errs[0] instanceof PoolClosedError, true);
    eq(errs[1] instanceof PoolClosedError, true);
    eq(closed, false, 'close is held open by the in-flight lease');
    await rejects(pool.acquire(), PoolClosedError, 'no lending after close');

    held.release(); // in-flight return while closing
    await closing;
    eq(closed, true);
    eq(pool.size, 0, 'returned in-flight instance is destroyed, no replacement created');
    // Every instance the pool ever made has been destroyed exactly once.
    for (const h of FakeHash.created) {
      eq(h.destroyed, true, `instance #${h.id} destroyed`);
      eq(h.destroyCalls, 1, `instance #${h.id} destroyed once`);
    }
  });

  it('close on an idle pool destroys idle instances immediately', async () => {
    const pool = new HashPool(() => new FakeHash(), { capacity: 2 });
    const a = await pool.acquire();
    const b = await pool.acquire();
    a.release();
    b.release();
    eq(pool.size, 2);
    await pool.close();
    eq(pool.size, 0);
    for (const h of FakeHash.created) eq(h.destroyCalls, 1);
    await rejects(pool.acquire(), PoolClosedError);
  });

  it('close() and release() interleave: multiple in-flight returns drain into close', async () => {
    const pool = new HashPool(() => new FakeHash(), { capacity: 3 });
    const a = await pool.acquire();
    const b = await pool.acquire();
    const c = await pool.acquire();
    let closed = false;
    const closing = pool.close().then(() => (closed = true));
    await flush();
    eq(closed, false);
    a.release();
    await flush();
    eq(closed, false, 'still waiting on two leases');
    b.release();
    await flush();
    eq(closed, false);
    c.release();
    await closing;
    eq(closed, true, 'last in-flight return resolves close');
    // A late release of a closed-pool lease is impossible (already released once above).
    throws(() => a.release(), /twice/);
  });

  it('close is idempotent and concurrent calls share resolution', async () => {
    const pool = new HashPool(() => new FakeHash(), { capacity: 1 });
    const held = await pool.acquire();
    let n = 0;
    const c1 = pool.close().then(() => n++);
    const c2 = pool.close().then(() => n++);
    await flush();
    eq(n, 0);
    held.release();
    await Promise.all([c1, c2]);
    eq(n, 2);
    await pool.close(); // repeatable after drain
  });

  it('waiter cancellation races safely with handoff (cancel loses, lease wins)', async () => {
    // Deterministic interleaving: release schedules the handoff microtask; abort in the same
    // flush window must not duplicate-settle or lose the permit.
    const pool = new HashPool(() => new FakeHash(), { capacity: 1 });
    const held = await pool.acquire();
    const ac = new AbortController();
    let lease: Awaited<ReturnType<typeof pool.acquire>> | undefined;
    let err: unknown;
    const w = pool
      .acquire(ac.signal)
      .then((l) => (lease = l))
      .catch((e) => (err = e));
    await flush();
    held.release(); // schedules resolve(hash)
    ac.abort(); // abort attempt after handoff is scheduled
    await w;
    await flush(2);
    if (lease) {
      eq(err, undefined);
      lease.release();
    } else {
      eq((err as Error).name, 'AbortError');
      // If abort won the race, the replacement must sit idle and be lendable right away.
      const retry = await pool.acquire();
      retry.release();
    }
    eq(pool.pending, 0);
    await pool.close();
    for (const h of FakeHash.created) eq(h.destroyCalls, 1);
  });

  it('factory failure on return leaves the lease valid and the slot intact', async () => {
    let fail = false;
    const pool = new HashPool(
      () => {
        if (fail) throw new Error('factory down');
        return new FakeHash();
      },
      { capacity: 1 }
    );
    const lease = await pool.acquire();
    fail = true;
    throws(() => lease.release(), /factory down/, 'factory error surfaces from release()');
    // Lease ownership is unchanged: capacity is not lost and a retry succeeds once recovered.
    eq(pool.size, 1);
    fail = false;
    lease.release();
    const retry = await pool.acquire();
    eq((retry.hash as FakeHash).id, 1, 'fresh empty instance after retry');
    retry.release();
    await pool.close();
  });

  it('factory options are forwarded on every creation, including replacements', async () => {
    const seen: number[] = [];
    const pool = new HashPool<FakeHash, { dkLen: number }>(
      (opts) => {
        seen.push(opts!.dkLen);
        return new FakeHash();
      },
      { capacity: 1, opts: { dkLen: 64 } }
    );
    await pool.acquire().then((l) => l.release()); // create + replacement
    await pool.acquire().then((l) => l.release());
    eql(seen, [64, 64, 64], 'initial, replacement-after-release, and next slot all see opts');
    await pool.close();
  });

  it('rejects invalid capacity or factory', () => {
    throws(() => new HashPool(() => new FakeHash(), { capacity: 0 }), TypeError);
    throws(() => new HashPool(() => new FakeHash(), { capacity: -1 }), TypeError);
    throws(() => new HashPool(() => new FakeHash(), { capacity: 1.5 }), TypeError);
    throws(
      // @ts-expect-error runtime check for non-function factory
      () => new HashPool({}, { capacity: 1 }),
      TypeError
    );
  });
});

if (import.meta.url === pathToFileURL(process.argv[1]).href) it.runWhen(import.meta.url);
