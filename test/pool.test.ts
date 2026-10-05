import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, throws } from 'node:assert';
import { pathToFileURL } from 'node:url';
import { sha256 } from '../src/sha2.ts';
import { HashPool, type Lease } from '../src/pool.ts';
import type { Hash } from '../src/utils.ts';

const flush = () => new Promise<void>((resolve) => setImmediate(resolve));

const sha256Factory = () => sha256.create();
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString('hex');

const SHA256_ABC = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
const SHA256_EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

function spyFactory() {
  const counts = new Map<Hash<any>, number>();
  const cons = () => {
    const h = sha256.create();
    const orig = h.destroy.bind(h);
    h.destroy = () => {
      counts.set(h, (counts.get(h) ?? 0) + 1);
      orig();
    };
    return h;
  };
  return { cons, counts };
}

describe('HashPool', () => {
  it('hands out a fresh empty instance after a return (no residue)', async () => {
    const pool = new HashPool(sha256Factory, { capacity: 1 });

    const first = await pool.acquire();
    first.hash.update(new Uint8Array([97, 98, 99]));
    eql(hex(first.hash.digest()), SHA256_ABC, 'first caller hashes abc');
    first.release();

    const second = await pool.acquire();
    second.hash.update(new Uint8Array());
    eql(hex(second.hash.digest()), SHA256_EMPTY, 'second caller gets empty digest, no residue');
    second.release();
    pool.close();
  });

  it('keeps state isolated when the second caller hashes more data', async () => {
    const pool = new HashPool(sha256Factory, { capacity: 1 });

    const a = await pool.acquire();
    a.hash.update(new Uint8Array([1, 2, 3]));
    a.release();

    const b = await pool.acquire();
    b.hash.update(new Uint8Array([1, 2, 3, 4, 5]));
    const expected = hex(
      sha256
        .create()
        .update(new Uint8Array([1, 2, 3, 4, 5]))
        .digest()
    );
    eql(hex(b.hash.digest()), expected, 'state was reset between callers');
    b.release();
    pool.close();
  });

  it('capacity limits concurrent leases', async () => {
    const pool = new HashPool(sha256Factory, { capacity: 2 });

    const l1 = await pool.acquire();
    const l2 = await pool.acquire();

    let l3: Lease<ReturnType<typeof sha256Factory>> | undefined;
    const w3 = pool.acquire().then((l) => (l3 = l));
    await flush();
    eql(l3, undefined, 'third lease waits at capacity');

    l1.release();
    await w3;
    eql(l3 !== undefined, true, 'third lease resolves after a permit returns');

    l2.release();
    l3!.release();
    pool.close();
  });

  it('waiters are served in FIFO order', async () => {
    const pool = new HashPool(sha256Factory, { capacity: 1 });

    const l1 = await pool.acquire();
    const order: number[] = [];
    const w1 = pool.acquire().then((l) => {
      order.push(1);
      return l;
    });
    const w2 = pool.acquire().then((l) => {
      order.push(2);
      return l;
    });
    await flush();

    l1.release();
    const lw1 = await w1;
    eql(order, [1], 'first waiter served first');

    lw1.release();
    await w2;
    eql(order, [1, 2], 'second waiter served next');
    pool.close();
  });

  it('cancelling a waiter does not consume a permit', async () => {
    const pool = new HashPool(sha256Factory, { capacity: 1 });

    const l1 = await pool.acquire();
    const controller = new AbortController();
    const w1 = pool.acquire(controller.signal);
    await flush();

    controller.abort(new Error('cancel'));
    await rejects(w1, /cancel/, 'cancelled waiter rejects');

    l1.release();
    const l2 = await pool.acquire();
    eql(hex(l2.hash.digest()), SHA256_EMPTY, 'permit still available after cancel');
    l2.release();
    pool.close();
  });

  it('a pre-aborted signal rejects immediately and never queues', async () => {
    const pool = new HashPool(sha256Factory, { capacity: 1 });
    const controller = new AbortController();
    controller.abort(new Error('pre'));
    await rejects(pool.acquire(controller.signal), /pre/);
    pool.close();
  });

  it('close wakes waiters and stops lending', async () => {
    const pool = new HashPool(sha256Factory, { capacity: 1 });

    const l1 = await pool.acquire();
    const w1 = pool.acquire();
    const w2 = pool.acquire();
    await flush();

    pool.close();
    await rejects(w1, /pool is closed/, 'waiter w1 woken by close');
    await rejects(w2, /pool is closed/, 'waiter w2 woken by close');
    await rejects(pool.acquire(), /pool is closed/, 'no lending after close');

    // In-flight return is still handled: state destroyed, permit retired, no re-lend.
    l1.release();
    await rejects(pool.acquire(), /pool is closed/, 'in-flight return does not re-lend');
  });

  it('close is idempotent and destroys idle instances', async () => {
    const pool = new HashPool(sha256Factory, { capacity: 2 });
    const l1 = await pool.acquire();
    const l2 = await pool.acquire();
    l1.release(); // builds an idle instance
    l2.release(); // replaces it (old idle destroyed once)
    pool.close();
    pool.close(); // no-op
    await rejects(pool.acquire(), /pool is closed/);
  });

  it('duplicate release is rejected', async () => {
    const pool = new HashPool(sha256Factory, { capacity: 1 });
    const l1 = await pool.acquire();
    l1.release();
    throws(() => l1.release(), /lease already released/, 'second release throws');
    pool.close();
  });

  it('destroy happens exactly once per instance', async () => {
    const { cons, counts } = spyFactory();
    const pool = new HashPool(cons, { capacity: 1 });

    // Finalized via digest(): digest() already destroys, so release must not destroy again.
    const a = await pool.acquire();
    a.hash.update(new Uint8Array([97, 98, 99]));
    a.hash.digest();
    a.release();
    eql(counts.get(a.hash), 1, 'finalized instance destroyed once');

    // Not finalized: release destroys exactly once.
    const b = await pool.acquire();
    b.hash.update(new Uint8Array([1, 2]));
    b.release();
    eql(counts.get(b.hash), 1, 'non-finalized instance destroyed once');

    // Explicit destroy before release: release must not destroy again.
    const c = await pool.acquire();
    c.hash.destroy();
    c.release();
    eql(counts.get(c.hash), 1, 'pre-destroyed instance destroyed once');

    pool.close();
  });

  it('rejects invalid options', () => {
    throws(() => new HashPool(sha256Factory, { capacity: 0 }), /positive integer/);
    throws(() => new HashPool(sha256Factory, { capacity: -1 }), /positive integer/);
    throws(() => new HashPool(sha256Factory, { capacity: 1.5 }), /positive integer/);
    throws(() => new HashPool(null as any), /hashCons/);
  });
});

it.runWhen(import.meta.url);
