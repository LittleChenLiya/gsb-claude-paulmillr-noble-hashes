/**
 * Explicit HKDF session: extract a SHA-256 PRK once from `salt || ikm`, then
 * derive many independent keys from `(label, context, length)` tuples using a
 * fixed, length-framed `info` string.
 *
 * Wire format of `info` (every length is validated BEFORE any concatenation,
 * so a malformed call can never produce an ambiguous framing):
 *
 * ```
 * info = "HKT1"                              (4 ASCII bytes, protocol/version magic)
 *      || uint16BE(labelUtf8ByteLength)      (2 bytes, 0..65535)
 *      || label                              (UTF-8 encoded, length counted in UTF-8 bytes)
 *      || uint16BE(contextLength)            (2 bytes, 0..65535)
 *      || context                            (raw application bytes)
 *      || uint16BE(outputLength)             (2 bytes, 0..255*32)
 * ```
 *
 * Lifecycle: the PRK lives only inside the returned session. {@link HKDFSession.destroy}
 * zeroizes it in place; after that every `derive` call throws a state error.
 * Inputs (`ikm`, `salt`, `context`) are never modified, and every derived key is
 * a fresh, independent buffer. The standalone {@link extract} / {@link expand}
 * primitives in `hkdf.ts` are intentionally unchanged.
 * @module
 */
import { expand, extract } from './hkdf.ts';
import { sha256 } from './sha2.ts';
import {
  abytes,
  anumber,
  clean,
  createView,
  utf8ToBytes,
  type TArg,
  type TRet,
} from './utils.ts';

/** Protocol magic: ASCII "HKT1" (HKDF transcript, version 1). */
const PROTOCOL_MAGIC = /* @__PURE__ */ Uint8Array.from([0x48, 0x4b, 0x54, 0x31]);
/** HKDF-SHA256 output cap: 255 * HashLen (RFC 5869 §2.3). */
const MAX_OUTPUT_LEN = 255 * sha256.outputLen;
/** Every framed length is a uint16, so 65535 is the hard ceiling. */
const MAX_FRAMED_LEN = 0xffff;

/**
 * An explicit HKDF-SHA256 session with an extracted PRK and a fixed info framing.
 */
export interface HKDFSession {
  /**
   * Derives an independent key for the given label / context / length tuple.
   * @param label - Application label, UTF-8 encoded; its byte length is framed
   *   as a uint16 and must be 0..65535 bytes.
   * @param context - Application context bytes, framed as a uint16 length.
   * @param length - Output length in bytes, 0..255*32.
   * @returns Freshly derived key bytes; never aliases the PRK or the inputs.
   * @throws If the session has been destroyed. {@link Error}
   * @throws If any argument has a wrong type or an out-of-range length. {@link TypeError} / {@link RangeError}
   */
  derive(label: string, context: TArg<Uint8Array>, length: number): TRet<Uint8Array>;
  /**
   * Zeroizes the internal PRK and permanently rejects further {@link derive} calls.
   * Idempotent: calling it more than once is a no-op.
   */
  destroy(): void;
}

class HKDFSessionImpl implements HKDFSession {
  // The extracted PRK is secret key material kept in one place; destroy() wipes it.
  #prk: Uint8Array | undefined;

  constructor(ikm: TArg<Uint8Array>, salt?: TArg<Uint8Array>) {
    // Extract once at creation: PRK = HMAC-SHA256(salt, ikm).
    // extract()/hmac() only read their inputs; callers' buffers are never modified.
    this.#prk = extract(sha256, ikm, salt);
  }

  derive(label: string, context: TArg<Uint8Array>, length: number): TRet<Uint8Array> {
    if (!this.#prk) throw new Error('HKDF session was destroyed');
    // Validate and encode every length BEFORE concatenation: a bad call must
    // throw without producing a half-built, ambiguous framing.
    if (typeof label !== 'string') throw new TypeError('"label" expected string');
    const labelBytes = utf8ToBytes(label);
    if (labelBytes.length > MAX_FRAMED_LEN)
      throw new RangeError('"label" UTF-8 byte length must be <= 65535');
    abytes(context, undefined, 'context');
    if (context.length > MAX_FRAMED_LEN)
      throw new RangeError('"context" length must be <= 65535');
    anumber(length, 'length');
    // 255*HashLen (8160) is stricter than the uint16 framing ceiling (65535),
    // so it is the only output-length bound we need to check.
    if (length > MAX_OUTPUT_LEN)
      throw new RangeError('"length" must be <= 255*HashLen (8160)');

    // info = magic || u16(labelLen) || label || u16(contextLen) || context || u16(outLen)
    const info = new Uint8Array(
      PROTOCOL_MAGIC.length +
        2 +
        labelBytes.length +
        2 +
        context.length +
        2
    );
    const view = createView(info);
    let offset = 0;
    info.set(PROTOCOL_MAGIC, offset);
    offset += PROTOCOL_MAGIC.length;
    view.setUint16(offset, labelBytes.length, false);
    offset += 2;
    info.set(labelBytes, offset);
    offset += labelBytes.length;
    view.setUint16(offset, context.length, false);
    offset += 2;
    info.set(context, offset);
    offset += context.length;
    view.setUint16(offset, length, false);

    // Standalone expand() never mutates the PRK: it works on fresh T/OKM buffers
    // and wipes its own scratch before returning. The returned key is therefore
    // an independent copy that callers can modify freely.
    return expand(sha256, this.#prk, info, length);
  }

  destroy(): void {
    // Overwrite the PRK before dropping the reference; idempotent like eskdf.expire().
    if (this.#prk) clean(this.#prk);
    this.#prk = undefined;
  }
}

/**
 * Creates an explicit HKDF-SHA256 session: extracts a 32-byte PRK from
 * `salt || ikm` immediately, then derives child keys via
 * {@link HKDFSession.derive} with a fixed, length-framed `info` string.
 *
 * @param ikm - Input keying material (the initial key). Read-only.
 * @param salt - Optional salt (non-secret random value); defaults to
 *   `HashLen` zero bytes, matching {@link extract}. Read-only.
 * @returns Frozen session object with {@link HKDFSession.derive} and
 *   {@link HKDFSession.destroy}.
 * @throws If `ikm` is not a byte array. {@link TypeError}
 * @example
 * Extract once, derive many independent keys, then wipe the PRK.
 * ```ts
 * import { hkdfSession } from '@noble/hashes/hkdf-session.js';
 * import { randomBytes } from '@noble/hashes/utils.js';
 * const session = hkdfSession(randomBytes(32), randomBytes(32));
 * const key = session.derive('my-app', new Uint8Array([1, 2, 3]), 32);
 * session.destroy(); // further derive() calls throw
 * ```
 */
export function hkdfSession(
  ikm: TArg<Uint8Array>,
  salt?: TArg<Uint8Array>
): TRet<HKDFSession> {
  abytes(ikm, undefined, 'ikm');
  const session = new HKDFSessionImpl(ikm, salt);
  return Object.freeze(session) as TRet<HKDFSession>;
}
