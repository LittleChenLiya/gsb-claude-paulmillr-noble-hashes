/**
 * HKT1: explicit, stateful session-key deriver on top of HKDF-SHA256 (RFC 5869).
 *
 * Construction runs `HKDF-Extract(salt, IKM)` once and keeps the resulting
 * SHA-256 pseudorandom key (PRK) inside the instance. Every `derive()` call
 * runs `HKDF-Expand(PRK, info, L)` with a self-delimiting, custom `info`:
 *
 * ```text
 * "HKT1" || u16be(label_byte_len) || label_utf8
 *       || u16be(context_len)     || context
 *       || u16be(output_len)
 * ```
 *
 * - The leading ASCII constant `HKT1` (4 bytes) domain-separates the protocol.
 * - Every variable-length field carries an explicit big-endian 16-bit length,
 *   so different `(label, context)` splits cannot collide: e.g. label `ab`
 *   with context `c` and label `a` with context `bc` produce different `info`.
 * - Label lengths count UTF-8 bytes, not JS UTF-16 code units.
 * - All lengths are validated before any byte is copied, and the output length
 *   is itself part of `info`, so distinct requested lengths derive distinct keys.
 *
 * Zeroization lifecycle: the constructor stores only the extracted PRK in a
 * private slot; caller-owned `ikm`, `salt` and `context` buffers are never
 * modified or retained. `destroy()` overwrites the PRK with zeros and drops the
 * reference; afterwards every `derive()` rejects with an explicit state error.
 * `destroy()` is idempotent. Each derived key is a freshly allocated,
 * independent copy, and the temporary `info` buffer is wiped after expansion.
 *
 * The plain stateless {@link hkdf}, {@link extract} and {@link expand}
 * functions are unaffected by this module.
 * @module
 */
import { expand, extract } from './hkdf.ts';
import { sha256 } from './sha2.ts';
import { abytes, anumber, clean, createView, utf8ToBytes, type TArg, type TRet } from './utils.ts';

/** Domain-separation prefix of every HKT1 info value (ASCII HKT1). */
const INFO_PREFIX: TRet<Uint8Array> = utf8ToBytes('HKT1');
/** Hash length of the fixed HKDF-SHA256 PRK, in bytes. */
const PRK_LEN = 32;
/** A 16-bit big-endian length prefix can address at most 2^16-1 bytes. */
const MAX_U16 = 0xffff;
/** RFC 5869 section 2.3 output ceiling for SHA-256: 255 * HashLen. */
const MAX_OKM_LEN = 255 * PRK_LEN; // 8160

/**
 * Builds the fixed HKT1 `info` frame described in the module header.
 * All inputs and lengths are fully validated before the result is allocated,
 * so no bytes are ever produced from an ambiguous or oversized field.
 * @param label - UTF-8 label string; its encoded byte length must fit in u16
 * @param context - caller-owned context bytes; length must fit in u16 (may be empty)
 * @param length - requested output length, framed as u16 and bounded to 1..255*32
 * @returns Freshly allocated info bytes; the caller owns wiping them.
 * @throws On non-string label or non-bytes context. {@link TypeError}
 * @throws On out-of-range or non-integer lengths. {@link RangeError}
 */
function buildInfo(label: string, context: TArg<Uint8Array>, length: number): TRet<Uint8Array> {
  if (typeof label !== 'string')
    throw new TypeError('"label" expected string, got type=' + typeof label);
  abytes(context, undefined, 'context');
  anumber(length, 'length');
  // Encode after type validation but before length validation: the UTF-8 byte
  // length, not the JS string length, is what gets framed and must fit in u16.
  const labelBytes = utf8ToBytes(label);
  try {
    if (labelBytes.length > MAX_U16)
      throw new RangeError('"label" UTF-8 byte length must be <= 65535, got ' + labelBytes.length);
    if (context.length > MAX_U16)
      throw new RangeError('"context" byte length must be <= 65535, got ' + context.length);
    // The u16 output-length field requires <= 65535; HKDF tightens this to 8160.
    if (length < 1 || length > MAX_OKM_LEN)
      throw new RangeError('"length" expected integer in 1..' + MAX_OKM_LEN + ', got ' + length);
    // Only now, after every length check passed, allocate and fill the frame.
    const info = new Uint8Array(
      INFO_PREFIX.length + 2 + labelBytes.length + 2 + context.length + 2
    );
    const view = createView(info);
    let pos = 0;
    info.set(INFO_PREFIX, pos);
    pos += INFO_PREFIX.length;
    view.setUint16(pos, labelBytes.length, false);
    pos += 2;
    info.set(labelBytes, pos);
    pos += labelBytes.length;
    view.setUint16(pos, context.length, false);
    pos += 2;
    info.set(context, pos);
    pos += context.length;
    view.setUint16(pos, length, false);
    return info as TRet<Uint8Array>;
  } finally {
    // Label bytes live only inside the framed info; wipe the temporary copy.
    clean(labelBytes);
  }
}

/**
 * Explicit multi-key session deriver. Instances are created with
 * `new HKT1(ikm, salt)`; use {@link HKT1.derive} to mint labeled keys and
 * {@link HKT1.destroy} to wipe the internal PRK at session end.
 */
export interface HKT1Deriver {
  /**
   * Derives `length` bytes for `label` under `context` via HKDF-Expand over
   * the session PRK and the fixed HKT1 info frame.
   * @param label - UTF-8 label, at most 65535 encoded bytes
   * @param context - context and application-specific bytes (may be empty), never modified
   * @param length - output size in bytes, 1..8160 (255*32); defaults to 32
   * @returns Independent, freshly allocated key bytes.
   */
  derive(label: string, context: TArg<Uint8Array>, length?: number): TRet<Uint8Array>;
  /**
   * Zeroizes the extracted PRK and permanently disables {@link HKT1.derive}.
   * Safe to call more than once.
   */
  destroy(): void;
}

/**
 * Stateful HKDF-SHA256 session deriver using the HKT1 info protocol.
 *
 * The constructor performs `PRK = HKDF-Extract(salt, IKM)` immediately.
 * `ikm` and `salt` are read once and never retained; only the independent
 * 32-byte PRK is held. Call {@link HKT1.destroy} when the session ends.
 * @param ikm - input keying material; caller-owned, never modified
 * @param salt - salt value (non-secret random value); caller-owned, never modified
 * @throws If `ikm` or `salt` is not a byte array. {@link TypeError}
 * @example
 * Derive labeled session keys and wipe the PRK when done.
 * ```ts
 * import { HKT1 } from '@noble/hashes/hkt1.js';
 * import { utf8ToBytes } from '@noble/hashes/utils.js';
 * const session = new HKT1(inputKey, salt);
 * const key1 = session.derive('encryption', utf8ToBytes('client-hello'), 32);
 * const key2 = session.derive('authentication', utf8ToBytes('client-hello'), 32);
 * session.destroy(); // wipes the PRK; further derive() calls throw
 * ```
 */
export class HKT1 implements HKT1Deriver {
  private prk: Uint8Array | undefined;

  constructor(ikm: TArg<Uint8Array>, salt: TArg<Uint8Array>) {
    abytes(ikm, undefined, 'ikm');
    abytes(salt, undefined, 'salt');
    // HMAC output is a freshly allocated buffer: the stored PRK never aliases
    // ikm, salt, or any caller-owned memory.
    this.prk = extract(sha256, ikm, salt);
  }

  derive(label: string, context: TArg<Uint8Array>, length: number = 32): TRet<Uint8Array> {
    const prk = this.prk;
    // Check the destroyed state before touching any derivation input.
    if (prk === undefined)
      throw new Error('HKT1 session is destroyed: derive() rejected after destroy()');
    const info = buildInfo(label, context, length);
    try {
      // Standalone expand() allocates its own OKM and never mutates prk.
      return expand(sha256, prk, info, length);
    } finally {
      clean(info);
    }
  }

  destroy(): void {
    const prk = this.prk;
    if (prk !== undefined) {
      clean(prk); // Overwrite the secret before dropping the only reference.
      this.prk = undefined;
    }
  }
}
