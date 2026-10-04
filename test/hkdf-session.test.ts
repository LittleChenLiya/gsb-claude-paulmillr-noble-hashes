import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, equal, throws } from 'node:assert';
import nodeCrypto from 'node:crypto';
import { hkdfSession } from '../src/hkdf-session.ts';
import { expand, extract } from '../src/hkdf.ts';
import { sha256 } from '../src/sha2.ts';
import {
  bytesToHex,
  concatBytes,
  createView,
  randomBytes,
  utf8ToBytes,
} from '../src/utils.ts';

// Hand-built reference implementation of the framed info wire format:
// "HKT1" || u16BE(labelUtf8ByteLength) || label || u16BE(contextLen) || context || u16BE(outLen)
function refInfo(label: string, context: Uint8Array, length: number): Uint8Array {
  const labelBytes = utf8ToBytes(label);
  const u16 = (n: number) => {
    const b = new Uint8Array(2);
    createView(b).setUint16(0, n, false);
    return b;
  };
  return concatBytes(
    utf8ToBytes('HKT1'),
    u16(labelBytes.length),
    labelBytes,
    u16(context.length),
    context,
    u16(length)
  );
}

describe('hkdf-session', () => {
  it('derives keys identical to manual extract/expand and node hkdfSync', () => {
    const ikm = randomBytes(32);
    const salt = randomBytes(32);
    const session = hkdfSession(ikm, salt);
    try {
      const prk = extract(sha256, ikm, salt);
      const cases: [string, Uint8Array, number][] = [
        ['', new Uint8Array(0), 0],
        ['a', new Uint8Array(0), 32],
        ['ab', new Uint8Array([3]), 32],
        ['a', new Uint8Array([2, 3, 4]), 64],
        ['my-app/v1', utf8ToBytes('user-42'), 8160],
        ['key', new Uint8Array(1), 1],
      ];
      for (const [label, context, length] of cases) {
        const info = refInfo(label, context, length);
        const expected = expand(sha256, prk, info, length);
        const got = session.derive(label, context, length);
        eql(got, expected, `expand mismatch for ${JSON.stringify([label, context.length, length])}`);
        // Node's hkdfSync rejects L=0 (RFC 5869 allows it; our expand handles it above).
        if (length > 0) {
          const nodeOut = new Uint8Array(
            nodeCrypto.hkdfSync('sha256', ikm, salt, info, length)
          );
          eql(got, nodeOut, `node hkdfSync mismatch for ${JSON.stringify([label, context.length, length])}`);
        }
      }
    } finally {
      session.destroy();
    }
  });

  it('framed info disambiguates label/context boundaries', () => {
    const session = hkdfSession(randomBytes(32), randomBytes(16));
    try {
      const info1 = bytesToHex(refInfo('ab', utf8ToBytes('c'), 32));
      const info2 = bytesToHex(refInfo('a', utf8ToBytes('bc'), 32));
      equal(info1 === info2, false, 'info strings must differ');
      const k1 = session.derive('ab', utf8ToBytes('c'), 32);
      const k2 = session.derive('a', utf8ToBytes('bc'), 32);
      equal(bytesToHex(k1) === bytesToHex(k2), false, 'keys must differ');
    } finally {
      session.destroy();
    }
  });

  it('repeated derive is consistent and labels/contexts/lengths separate keys', () => {
    const session = hkdfSession(randomBytes(32), randomBytes(32));
    try {
      const ctx = new Uint8Array([9, 8, 7]);
      const a = session.derive('label', ctx, 32);
      const b = session.derive('label', ctx, 32);
      eql(a, b, 'same tuple must re-derive identically');
      equal(a === b, false, 'repeated derives must not alias the same buffer');
      equal(
        bytesToHex(session.derive('label2', ctx, 32)) === bytesToHex(a),
        false,
        'different label must separate keys'
      );
      equal(
        bytesToHex(session.derive('label', new Uint8Array([9, 8, 6]), 32)) === bytesToHex(a),
        false,
        'different context must separate keys'
      );
      equal(
        bytesToHex(session.derive('label', ctx, 64)) === bytesToHex(a),
        false,
        'different length must separate keys'
      );
      // Mutating one derived buffer must not affect later derivations.
      a[0] ^= 0xff;
      eql(session.derive('label', ctx, 32), b, 'derived keys must be independent copies');
    } finally {
      session.destroy();
    }
  });

  it('counts label length in UTF-8 bytes and validates framing bounds', () => {
    const ikm = new Uint8Array(32).fill(7);
    const session = hkdfSession(ikm);
    try {
      // 'é' is 2 UTF-8 bytes: 'aé' (3 bytes) must frame differently than 'ab' (2 bytes),
      // and the result must match a manual expand over the UTF-8-framed info.
      const prk = extract(sha256, ikm);
      const k = session.derive('aé', new Uint8Array(0), 32);
      eql(k, expand(sha256, prk, refInfo('aé', new Uint8Array(0), 32), 32));
      equal(
        bytesToHex(k) === bytesToHex(session.derive('ab', new Uint8Array(0), 32)),
        false,
        'multibyte label framing must differ from same-length ASCII label'
      );
      // 65535 UTF-8 bytes is the largest framable label; 65536 must throw before concatenation.
      const big = 'a'.repeat(65535);
      equal(session.derive(big, new Uint8Array(0), 1).length, 1);
      throws(() => session.derive('a'.repeat(65536), new Uint8Array(0), 1));
      // Context is framed the same way.
      equal(session.derive('x', new Uint8Array(65535), 1).length, 1);
      throws(() => session.derive('x', new Uint8Array(65536), 1));
    } finally {
      session.destroy();
    }
  });

  it('enforces the 255*32 output cap', () => {
    const session = hkdfSession(randomBytes(32));
    try {
      equal(session.derive('cap', new Uint8Array(0), 0).length, 0);
      equal(session.derive('cap', new Uint8Array(0), 8160).length, 8160);
      throws(() => session.derive('cap', new Uint8Array(0), 8161));
      throws(() => session.derive('cap', new Uint8Array(0), -1));
      throws(() => session.derive('cap', new Uint8Array(0), 1.5));
    } finally {
      session.destroy();
    }
  });

  it('destroy zeroizes the PRK and rejects further derives with a state error', () => {
    const session = hkdfSession(randomBytes(32), randomBytes(32));
    session.derive('before-destroy', new Uint8Array(0), 32);
    session.destroy();
    session.destroy(); // idempotent
    throws(
      () => session.derive('after-destroy', new Uint8Array(0), 32),
      /destroyed/,
      'derive after destroy must report a clear state error'
    );
  });

  it('session object is frozen', () => {
    const session = hkdfSession(randomBytes(32));
    try {
      equal(Object.isFrozen(session), true, 'session must be frozen');
    } finally {
      session.destroy();
    }
  });

  it('never mutates caller inputs', () => {
    const ikm = randomBytes(32);
    const salt = randomBytes(32);
    const ctx = randomBytes(16);
    const snapshot = concatBytes(ikm, salt, ctx);
    const session = hkdfSession(ikm, salt);
    try {
      session.derive('inputs', ctx, 8160);
      eql(concatBytes(ikm, salt, ctx), snapshot, 'ikm/salt/context must be untouched');
    } finally {
      session.destroy();
    }
  });

  it('validates argument types', () => {
    const session = hkdfSession(randomBytes(32));
    try {
      throws(() => session.derive(123 as any, new Uint8Array(0), 32));
      throws(() => session.derive('x', 'not-bytes' as any, 32));
      throws(() => session.derive('x', new Uint8Array(0), '32' as any));
      throws(() => hkdfSession('not-bytes' as any));
    } finally {
      session.destroy();
    }
  });
});

it.runWhen(import.meta.url);
