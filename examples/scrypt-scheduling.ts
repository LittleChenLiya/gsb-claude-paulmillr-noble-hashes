/**
 * Terminal demo of scryptAsync explicit work-budget scheduling.
 *
 * Run: npm run demo:scrypt   (finishes in a few seconds, well under 90s)
 *
 * Prints scheduling and cancellation status only — never any key material.
 */
import { scryptAsync } from '../src/scrypt.ts';

// Public demo inputs, not real credentials.
const PASSWORD = 'demo-password';
const SALT = 'demo-salt';
const PARAMS = { N: 2 ** 15, r: 8, p: 1, dkLen: 32 };

const redact = (key: Uint8Array) => '<' + key.length + '-byte derived key: redacted>';
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

// 1) Full derivation under an explicit work budget.
{
  const started = Date.now();
  let yields = 0;
  let last = { done: 0, total: 0 };
  const key = await scryptAsync(PASSWORD, SALT, {
    ...PARAMS,
    yieldEvery: 4096,
    onYield: (info) => {
      yields++;
      last = info;
      return tick();
    },
  });
  console.log('[derive] status: completed');
  console.log('[derive] key:', redact(key));
  console.log(
    '[derive] mixed ' +
      last.total +
      ' work units in ' +
      yields +
      ' yields (last yield at ' +
      last.done +
      '), elapsed: ' +
      (Date.now() - started) +
      'ms'
  );
}

// 2) Mid-derivation cancellation: abort after half of the mixing units.
{
  const controller = new AbortController();
  let yields = 0;
  try {
    await scryptAsync(PASSWORD, SALT, {
      ...PARAMS,
      yieldEvery: 2048,
      signal: controller.signal,
      onYield: ({ done, total }) => {
        yields++;
        if (done / total >= 0.5) controller.abort();
        return tick();
      },
    });
    console.log('[cancel] status: FAILED (derivation unexpectedly completed)');
    process.exitCode = 1;
  } catch (e) {
    console.log(
      '[cancel] status: cancelled after ' + yields + ' yields (' + (e as Error).name + ')'
    );
    console.log('[cancel] intermediate buffers wiped, no partial key returned');
  }
}

// 3) Pre-cancelled signal: rejects before any mixing work.
{
  const controller = new AbortController();
  controller.abort();
  try {
    await scryptAsync(PASSWORD, SALT, { ...PARAMS, yieldEvery: 2048, signal: controller.signal });
    console.log('[pre-cancel] status: FAILED (derivation unexpectedly completed)');
    process.exitCode = 1;
  } catch (e) {
    console.log('[pre-cancel] status: rejected before any work (' + (e as Error).name + ')');
  }
}
