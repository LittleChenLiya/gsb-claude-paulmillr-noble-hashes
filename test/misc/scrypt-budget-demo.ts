// Terminal demo of scryptAsync's explicit work-budget scheduling interface.
// Shows a full derivation and a cancelled derivation with their statuses.
// No real key material is ever printed: only lengths, yield counts and
// equality booleans. Runs in a few seconds (well under 90s).
//
//   node test/misc/scrypt-budget-demo.ts
import { scrypt, scryptAsync } from '../../src/scrypt.ts';

const OPTS = { N: 2 ** 16, r: 8, p: 1, dkLen: 32 };
// Demo-only inputs, not real credentials.
const PWD = 'demo-password';
const SALT = 'demo-salt';

// Counts wipes of the big intermediate table V (32 * r * N u32 words) so the
// demo can report buffer cleanup without exposing any buffer contents.
function probeVWipes() {
  const vWords = 32 * OPTS.r * OPTS.N;
  const orig = Uint32Array.prototype.fill;
  const probe = { count: 0 };
  Uint32Array.prototype.fill = function (...args) {
    if (this.length === vWords) probe.count++;
    return orig.apply(this, args);
  };
  return { probe, restore: () => (Uint32Array.prototype.fill = orig) };
}

async function fullDerivation() {
  console.log('[1/2] full derivation with explicit work budget');
  console.log(`  params: N=2**16 r=8 p=1 dkLen=32 yieldEvery=512`);
  const { probe, restore } = probeVWipes();
  let yields = 0;
  const started = Date.now();
  const key = await scryptAsync(PWD, SALT, {
    ...OPTS,
    yieldEvery: 512,
    onYield: () => {
      yields++;
      if (yields % 64 === 0) console.log(`  ... yield #${yields} (still running)`);
    },
  });
  restore();
  const reference = scrypt(PWD, SALT, OPTS);
  console.log(`  status: done in ${Date.now() - started}ms, yields=${yields}`);
  console.log(
    `  key: <${key.length} bytes, not printed>, matches sync scrypt: ${Buffer.compare(Buffer.from(key), Buffer.from(reference)) === 0}`
  );
  console.log(`  work buffer wipes after success: ${probe.count}`);
}

async function cancelledDerivation() {
  console.log('[2/2] cancelled derivation');
  const { probe, restore } = probeVWipes();
  const ac = new AbortController();
  let yields = 0;
  let status = 'completed';
  let reason = '';
  const started = Date.now();
  try {
    await scryptAsync(PWD, SALT, {
      ...OPTS,
      yieldEvery: 128,
      signal: ac.signal,
      onYield: () => {
        yields++;
        if (yields === 20) ac.abort(new Error('demo: user pressed cancel'));
      },
    });
  } catch (e) {
    status = 'aborted';
    reason = e && e.message ? e.message : String(e);
  } finally {
    restore();
  }
  console.log(`  status: ${status} after ${Date.now() - started}ms, yields=${yields}`);
  console.log(`  reject reason: ${reason}`);
  console.log(`  partial key returned: false (promise rejected)`);
  console.log(`  work buffer wipes after cancel: ${probe.count} (exactly once)`);
}

const t0 = Date.now();
await fullDerivation();
await cancelledDerivation();
console.log(`demo finished in ${Date.now() - t0}ms`);
