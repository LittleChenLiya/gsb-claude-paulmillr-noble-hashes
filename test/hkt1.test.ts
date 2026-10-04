import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, notDeepStrictEqual as notEql, throws } from 'node:assert';
import * as nodeCrypto from 'node:crypto';
import { expand, extract } from '../src/hkdf.ts';
import { HKT1 } from '../src/hkt1.ts';
import { sha256 } from '../src/sha2.ts';
import { clean, concatBytes, utf8ToBytes } from '../src/utils.ts';

// Hand-built reference frame:
//   "HKT1" | u16be(labelLen) | utf8(label) | u16be(contextLen) | context | u16be(outLen)
function manualInfo(label: string, context: Uint8Array, length: number): Uint8Array {
  const labelBytes = utf8ToBytes(label);
  const lenBytes = (n: number) => Uint8Array.of((n >>> 8) & 0xff, n & 0xff);
  return concatBytes(
    utf8ToBytes('HKT1'),
    lenBytes(labelBytes.length),
    labelBytes,
    lenBytes(context.length),
    context,
    lenBytes(length)
  );
}

describe('HKT1', () => {
  const ikm = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
  const salt = Uint8Array.from({ length: 16 }, (_, i) => 0xa0 + i);

  it('acceptance: output equals manual hkdf.expand over the exact info bytes', () => {
    const prk = extract(sha256, ikm, salt);
    const session = new HKT1(ikm, salt);
    try {
      for (const [label, ctxStr, length] of [
        ['ab', 'c', 32],
        ['a', 'bc', 32],
        ['', '', 1], // empty label and empty context are both framed
        ['encryption', 'client-hello', 48],
        ['长いラベル', 'コンテキスト', 64], // multi-byte UTF-8
      ] as const) {
        const context = utf8ToBytes(ctxStr);
        const info = manualInfo(label, context, length);
        eql(session.derive(label, context, length), expand(sha256, prk, info, length));
        eql(info.slice(0, 4), utf8ToBytes('HKT1'));
      }
    } finally {
      session.destroy();
    }
  });

  it('acceptance: (ab,c) and (a,bc) produce different info, hence different keys', () => {
    const c1 = utf8ToBytes('c');
    const c2 = utf8ToBytes('bc');
    notEql(manualInfo('ab', c1, 32), manualInfo('a', c2, 32));
    const session = new HKT1(ikm, salt);
    try {
      notEql(session.derive('ab', c1, 32), session.derive('a', c2, 32));
      // Same key material is also distinct once the requested length changes,
      // because output length is part of the info frame.
      notEql(session.derive('ab', c1, 32), session.derive('ab', c1, 33));
    } finally {
      session.destroy();
    }
  });

  it('repeated derive is deterministic and independent across sessions/copies', () => {
    const a = new HKT1(ikm, salt);
    const b = new HKT1(ikm, salt);
    try {
      const context = utf8ToBytes('session-context');
      const first = a.derive('label', context, 32);
      eql(a.derive('label', context, 32), first);
      eql(b.derive('label', context, 32), first);
      // Returned key is an independent copy: mutating it changes no later result.
      first.fill(0xff);
      const again = a.derive('label', context, 32);
      eql(again, b.derive('label', context, 32));
      notEql(again, new Uint8Array(32).fill(0xff));
    } finally {
      a.destroy();
      b.destroy();
    }
  });

  it('cross-checks HKT1 output against node:crypto hkdfSync with the same info', () => {
    if (typeof nodeCrypto.hkdfSync !== 'function') return;
    const session = new HKT1(ikm, salt);
    try {
      for (const [label, ctxStr, length] of [
        ['ab', 'c', 32],
        ['a', 'bc', 42],
        ['key', '', 8160],
      ] as const) {
        const context = utf8ToBytes(ctxStr);
        const info = manualInfo(label, context, length);
        const node = new Uint8Array(nodeCrypto.hkdfSync('sha256', ikm, salt, info, length));
        eql(session.derive(label, context, length), node);
      }
    } finally {
      session.destroy();
    }
  });

  it('never modifies caller-owned ikm, salt or context', () => {
    const ikmCopy = ikm.slice();
    const saltCopy = salt.slice();
    const context = utf8ToBytes('do-not-touch');
    const contextCopy = context.slice();
    const session = new HKT1(ikm, salt);
    try {
      session.derive('label', context, 32);
      session.derive('other', context, 64);
      eql(ikm, ikmCopy);
      eql(salt, saltCopy);
      eql(context, contextCopy);
    } finally {
      session.destroy();
    }
    eql(ikm, ikmCopy);
    eql(salt, saltCopy);
    eql(context, contextCopy);
  });

  it('length limits: 1..255*32 = 8160', () => {
    const context = new Uint8Array();
    const session = new HKT1(ikm, salt);
    try {
      eql(session.derive('max', context, 1).length, 1);
      eql(session.derive('max', context, 8160).length, 8160);
      throws(() => session.derive('max', context, 0), /"length" expected integer in 1\.\.8160/);
      throws(() => session.derive('max', context, 8161), /"length" expected integer in 1\.\.8160/);
      for (const bad of [-1, 1.5, NaN, 2 ** 53, true, '32', null, undefined]) {
        if (bad === undefined) continue; // default-arg path is valid
        throws(() => session.derive('max', context, bad as number));
      }
    } finally {
      session.destroy();
    }
  });

  it('validates inputs and u16-prefixed UTF-8/context lengths before framing', () => {
    const session = new HKT1(ikm, salt);
    try {
      throws(() => session.derive(42 as any, new Uint8Array(), 32), /"label" expected string/);
      throws(() => session.derive('label', 'context' as any, 32), /"context" expected Uint8Array/);
      throws(() => session.derive('label', new Uint8Array(65536), 32), /"context" byte length/);
      // Label length is measured in UTF-8 bytes: 21846 astral chars encode to 65538 bytes,
      // even though the JS string is 21846 UTF-16 code units.
      throws(
        () => session.derive('😀'.repeat(21846), new Uint8Array(), 32),
        /"label" UTF-8 byte length must be <= 65535/
      );
      // An astral label under the byte cap still frames on UTF-8 length (2 bytes per char).
      eql(session.derive('😀', new Uint8Array(), 2).length, 2);
    } finally {
      session.destroy();
    }
    throws(() => new HKT1(undefined as any, salt), /"ikm" expected Uint8Array/);
    throws(() => new HKT1(ikm, 'salt' as any), /"salt" expected Uint8Array/);
  });

  it('acceptance: destroy zeroizes the PRK and rejects further derive with a state error', () => {
    const expectedPrk = extract(sha256, ikm, salt);
    let wipedPrk: Uint8Array | undefined;
    const fill = Uint8Array.prototype.fill;
    Uint8Array.prototype.fill = function (value: any, start?: any, end?: any) {
      if (value === 0 && this.length === 32) wipedPrk = this.slice(0);
      return fill.call(this, value, start, end);
    };
    const session = new HKT1(ikm, salt);
    try {
      // Sanity: the instance derives correctly while alive.
      eql(
        session.derive('ab', utf8ToBytes('c'), 32),
        expand(sha256, expectedPrk, manualInfo('ab', utf8ToBytes('c'), 32), 32)
      );
    } finally {
      session.destroy();
      Uint8Array.prototype.fill = fill;
    }
    // destroy() wiped exactly the extracted PRK buffer (captured pre-zeroization).
    eql(wipedPrk, expectedPrk);
    // Post-destroy derives fail before doing any work, with an explicit state message.
    throws(() => session.derive('ab', utf8ToBytes('c'), 32), /destroyed/);
    throws(() => session.derive('ab', utf8ToBytes('c'), 32), {
      message: 'HKT1 session is destroyed: derive() rejected after destroy()',
    });
    // destroy() is idempotent and safe after a failed derive.
    session.destroy();
    session.destroy();
    clean(expectedPrk);
  });

  it('plain HKDF functions remain usable alongside HKT1', () => {
    const info = utf8ToBytes('plain');
    const stateless = expand(sha256, extract(sha256, ikm, salt), info, 32);
    eql(stateless, new Uint8Array(nodeCrypto.hkdfSync('sha256', ikm, salt, info, 32)));
  });
});

it.runWhen(import.meta.url);
