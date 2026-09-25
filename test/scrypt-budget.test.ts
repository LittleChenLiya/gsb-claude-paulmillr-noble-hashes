// Tests for the explicit work-budget scheduling interface of scryptAsync
// (yieldEvery / onYield / signal). All vectors are public RFC 7914 test
// vectors; no real passwords are used anywhere in this file.
import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, rejects, throws } from 'node:assert';
import { pathToFileURL } from 'node:url';
import { scrypt, scryptAsync } from '../src/scrypt.ts';
import { hexToBytes } from '../src/utils.ts';

// RFC 7914 section 12, first official scrypt test vector (public, fixed).
const RFC7914_VECTOR = {
  P: '',
  S: '',
  N: 16,
  r: 1,
  p: 1,
  dkLen: 64,
  exp:
    '77d6576238657b203b19ca42c18a0497' +
    'f16b4844e3074ae8dfdffa3fede21442' +
    'fcd0069ded0948f8326a753a0fc81f17' +
    'e8d3e0fb2e0d3628cf35e20c38d18906',
};
const VECTOR_OPTS = {
  N: RFC7914_VECTOR.N,
  r: RFC7914_VECTOR.r,
  p: RFC7914_VECTOR.p,
  dkLen: RFC7914_VECTOR.dkLen,
};
const VECTOR_KEY = hexToBytes(RFC7914_VECTOR.exp);
// Total core BlockMix work units of a derivation: 2 * N * p.
const totalUnits = (opts: { N: number; p: number }) => 2 * opts.N * opts.p;
// Yield points happen before a unit when the budget is exhausted:
// units 1..B run, yield, units B+1..2B run, yield, ... => floor((total - 1) / B).
const expectedYields = (units: number, budget: number) => Math.floor((units - 1) / budget);

// Counts how many times a Uint32Array of exactly `length` elements is filled.
// scrypt's intermediate table V (the big buffer) is a Uint32Array of
// 32 * r * N words, so this observes its wipe without touching key material.
function probeFillCount(length: number) {
  const orig = Uint32Array.prototype.fill;
  const probe = { count: 0 };
  Uint32Array.prototype.fill = function (this: Uint32Array, ...args: any[]) {
    if (this.length === length) probe.count++;
    return (orig as any).apply(this, args);
  } as any;
  return {
    probe,
    restore() {
      Uint32Array.prototype.fill = orig;
    },
  };
}

describe('scryptAsync work budget scheduling', () => {
  it('derives the RFC 7914 vector identically for every budget', async () => {
    const syncKey = scrypt(RFC7914_VECTOR.P, RFC7914_VECTOR.S, VECTOR_OPTS);
    eql(syncKey, VECTOR_KEY, 'sync vector');
    const budgets = [undefined, 1, 2, 3, 7, 16, 32, 1000];
    for (const yieldEvery of budgets) {
      const key = await scryptAsync(RFC7914_VECTOR.P, RFC7914_VECTOR.S, {
        ...VECTOR_OPTS,
        ...(yieldEvery === undefined ? {} : { yieldEvery }),
      });
      eql(key, VECTOR_KEY, `budget=${yieldEvery}`);
      eql(key, syncKey, `budget=${yieldEvery} matches sync`);
    }
  });

  it('counting yield observes deterministic segmentation', async () => {
    const units = totalUnits(VECTOR_OPTS); // 2 * 16 * 1 = 32
    for (const budget of [1, 4, 5, 32, 64]) {
      let yields = 0;
      const progressAtYield: number[] = [];
      let progressCalls = 0;
      const key = await scryptAsync(RFC7914_VECTOR.P, RFC7914_VECTOR.S, {
        ...VECTOR_OPTS,
        yieldEvery: budget,
        onYield: () => {
          yields++;
          progressAtYield.push(progressCalls);
        },
        onProgress: () => {
          progressCalls++;
        },
      });
      eql(key, VECTOR_KEY, `budget=${budget} key`);
      eql(yields, expectedYields(units, budget), `budget=${budget} yield count`);
      // Each yield happens exactly after budget-sized segments of core work.
      for (let i = 0; i < yields; i++)
        eql(progressAtYield[i], (i + 1) * budget, `budget=${budget} segment ${i}`);
    }
  });

  it('budget changes yield frequency, not the mixing order', async () => {
    // Record the BlockMix completion sequence via onProgress fractions:
    // identical mixing order => identical progress traces for any budget.
    const traces: number[][] = [];
    for (const yieldEvery of [1, 6, 31]) {
      const trace: number[] = [];
      await scryptAsync(RFC7914_VECTOR.P, RFC7914_VECTOR.S, {
        ...VECTOR_OPTS,
        yieldEvery,
        onYield: () => {},
        onProgress: (fraction) => trace.push(fraction),
      });
      traces.push(trace);
    }
    eql(traces[1], traces[0], 'trace budget=6 vs budget=1');
    eql(traces[2], traces[0], 'trace budget=31 vs budget=1');
    eql(traces[0].length, totalUnits(VECTOR_OPTS), 'one progress tick per work unit');
  });

  it('rejects invalid budgets and scheduler options', async () => {
    for (const yieldEvery of [0, -1, 2.5, NaN, Infinity, '4', true, {}, []] as any[]) {
      throws(
        () => scrypt(RFC7914_VECTOR.P, RFC7914_VECTOR.S, { ...VECTOR_OPTS, yieldEvery }),
        `sync yieldEvery=${String(yieldEvery)}`
      );
      await rejects(
        () => scryptAsync(RFC7914_VECTOR.P, RFC7914_VECTOR.S, { ...VECTOR_OPTS, yieldEvery }),
        `async yieldEvery=${String(yieldEvery)}`
      );
    }
    for (const onYield of [1, 'x', true, {}] as any[]) {
      await rejects(
        () => scryptAsync(RFC7914_VECTOR.P, RFC7914_VECTOR.S, { ...VECTOR_OPTS, onYield }),
        `onYield=${String(onYield)}`
      );
    }
    for (const signal of [1, 'x', true, { aborted: 'no' }] as any[]) {
      await rejects(
        () => scryptAsync(RFC7914_VECTOR.P, RFC7914_VECTOR.S, { ...VECTOR_OPTS, signal }),
        `signal=${String(signal)}`
      );
    }
    // A valid budget is accepted by (and ignored in) the sync variant: same key.
    eql(
      scrypt(RFC7914_VECTOR.P, RFC7914_VECTOR.S, { ...VECTOR_OPTS, yieldEvery: 4 }),
      VECTOR_KEY,
      'sync ignores valid budget'
    );
  });

  it('pre-cancelled signal rejects before any work and wipes buffers once', async () => {
    const vWords = 32 * VECTOR_OPTS.r * VECTOR_OPTS.N;
    const { probe, restore } = probeFillCount(vWords);
    try {
      const ac = new AbortController();
      const reason = new Error('cancelled before start');
      ac.abort(reason);
      let yields = 0;
      let caught: unknown;
      try {
        await scryptAsync(RFC7914_VECTOR.P, RFC7914_VECTOR.S, {
          ...VECTOR_OPTS,
          yieldEvery: 1,
          onYield: () => {
            yields++;
          },
          signal: ac.signal,
        });
      } catch (e) {
        caught = e;
      }
      eql(caught, reason, 'rejects with signal.reason');
      eql(yields, 0, 'no work rounds happened');
      eql(probe.count, 1, 'big buffer wiped exactly once');
    } finally {
      restore();
    }
  });

  it('mid-derivation cancel stops work, wipes buffers once, returns no key', async () => {
    const opts = { N: 1024, r: 8, p: 1, dkLen: 32 };
    const vWords = 32 * opts.r * opts.N;
    const { probe, restore } = probeFillCount(vWords);
    try {
      const ac = new AbortController();
      const reason = new Error('user cancelled');
      let yields = 0;
      let caught: unknown;
      try {
        await scryptAsync('demo-password', 'demo-salt', {
          ...opts,
          yieldEvery: 8,
          signal: ac.signal,
          onYield: () => {
            yields++;
            if (yields === 3) ac.abort(reason);
          },
        });
      } catch (e) {
        caught = e;
      }
      eql(caught, reason, 'rejects with signal.reason');
      eql(yields, 3, 'stopped at the abort point, not earlier or later');
      eql(yields < expectedYields(totalUnits(opts), 8), true, 'did not run to completion');
      eql(probe.count, 1, 'big buffer wiped exactly once');
      // A later uncancelled call with the same inputs still derives correctly.
      const key = await scryptAsync('demo-password', 'demo-salt', opts);
      eql(key, scrypt('demo-password', 'demo-salt', opts), 'post-cancel derivation intact');
    } finally {
      restore();
    }
  });

  it('yield callback errors are failures: cleanup happens exactly once', async () => {
    const vWords = 32 * VECTOR_OPTS.r * VECTOR_OPTS.N;
    const { probe, restore } = probeFillCount(vWords);
    try {
      const boom = new Error('yield hook failed');
      const ac = new AbortController();
      let calls = 0;
      let caught: unknown;
      try {
        await scryptAsync(RFC7914_VECTOR.P, RFC7914_VECTOR.S, {
          ...VECTOR_OPTS,
          yieldEvery: 2,
          signal: ac.signal, // also aborted: two failure sources, one cleanup
          onYield: () => {
            calls++;
            ac.abort(new Error('abort racing yield failure'));
            throw boom;
          },
        });
      } catch (e) {
        caught = e;
      }
      eql(calls, 1, 'derivation stopped at first failing yield');
      eql(caught, boom, 'yield error propagates');
      eql(probe.count, 1, 'buffers wiped exactly once despite two failure sources');
    } finally {
      restore();
    }
  });

  it('onProgress errors in the budgeted path clean up exactly once', async () => {
    const vWords = 32 * VECTOR_OPTS.r * VECTOR_OPTS.N;
    const { probe, restore } = probeFillCount(vWords);
    try {
      const boom = new Error('progress hook failed');
      let caught: unknown;
      try {
        await scryptAsync(RFC7914_VECTOR.P, RFC7914_VECTOR.S, {
          ...VECTOR_OPTS,
          yieldEvery: 4,
          onYield: () => {},
          onProgress: () => {
            throw boom;
          },
        });
      } catch (e) {
        caught = e;
      }
      eql(caught, boom, 'progress error propagates');
      eql(probe.count, 1, 'buffers wiped exactly once');
    } finally {
      restore();
    }
  });

  it('concurrent derivations with different budgets do not interfere', async () => {
    const opts = { N: 256, r: 8, p: 2, dkLen: 48 };
    const expected = scrypt('concurrent-demo', 'public-salt', opts);
    const units = totalUnits(opts);
    const run = async (yieldEvery: number) => {
      let yields = 0;
      const key = await scryptAsync('concurrent-demo', 'public-salt', {
        ...opts,
        yieldEvery,
        onYield: () => {
          yields++;
        },
      });
      return { key, yields };
    };
    const [a, b, c] = await Promise.all([run(3), run(64), run(1000)]);
    for (const [name, res] of [
      ['a', a],
      ['b', b],
      ['c', c],
    ] as const) {
      eql(res.key, expected, `${name} key matches sync`);
    }
    eql(a.yields, expectedYields(units, 3), 'a yield count');
    eql(b.yields, expectedYields(units, 64), 'b yield count');
    eql(c.yields, expectedYields(units, 1000), 'c yield count');
  });

  it('aborting one of two concurrent derivations leaves the other intact', async () => {
    const opts = { N: 512, r: 8, p: 1, dkLen: 32 };
    const expected = scrypt('shared-demo', 'public-salt', opts);
    const ac = new AbortController();
    const reason = new Error('only this one');
    let cancelled: unknown;
    const [survivor] = await Promise.all([
      scryptAsync('shared-demo', 'public-salt', { ...opts, yieldEvery: 16 }),
      scryptAsync('shared-demo', 'public-salt', {
        ...opts,
        yieldEvery: 4,
        signal: ac.signal,
        onYield: () => ac.abort(reason),
      }).catch((e) => {
        cancelled = e;
      }),
    ]);
    eql(cancelled, reason, 'cancelled derivation rejected');
    eql(survivor, expected, 'concurrent derivation unaffected');
  });

  it('onYield may be async and lets host timers run', async () => {
    let timerFired = false;
    const timer = new Promise<void>((resolve) =>
      setTimeout(() => {
        timerFired = true;
        resolve();
      }, 0)
    );
    const key = await scryptAsync(RFC7914_VECTOR.P, RFC7914_VECTOR.S, {
      ...VECTOR_OPTS,
      yieldEvery: 2,
      onYield: () => new Promise((resolve) => setTimeout(resolve, 0)),
    });
    eql(key, VECTOR_KEY, 'key with async yield hook');
    const firedDuringKdf = timerFired;
    await timer;
    eql(firedDuringKdf, true, 'host timer ran during derivation');
  });

  it('default call without scheduling options stays compatible', async () => {
    const key = await scryptAsync(RFC7914_VECTOR.P, RFC7914_VECTOR.S, VECTOR_OPTS);
    eql(key, VECTOR_KEY, 'default async vector');
    const keyTick = await scryptAsync(RFC7914_VECTOR.P, RFC7914_VECTOR.S, {
      ...VECTOR_OPTS,
      asyncTick: 0,
    });
    eql(keyTick, VECTOR_KEY, 'asyncTick-only vector');
  });
});

it.runWhen(import.meta.url);
