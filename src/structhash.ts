/**
 * Explicit structured digest protocol on top of SHA-256.
 *
 * Hashing `concatBytes(a, b, c)` is ambiguous: the boundary between fields is lost,
 * so `["ab", "c"]` and `["a", "bc"]` collide. This module instead hashes an explicit
 * byte encoding where every field carries a type tag, a fixed-width length and its
 * content, which makes field boundaries and value types unambiguous:
 *
 * ```txt
 * message  := preamble field*
 * preamble := MAGIC u32be(version)             // domain separation + protocol version
 * MAGIC    := "noble-struct-hash" || 0x00      // 18 bytes, ASCII + NUL
 * field    := name value
 * name     := TAG_STRING u32be(len) utf8       // field name, always a UTF-8 string
 * value    := TAG_BYTES  u32be(len) bytes      // declared bytes (Uint8Array)
 *           | TAG_STRING u32be(len) utf8       // declared UTF-8 string
 *           | TAG_UINT   u32be(8) u64be        // declared unsigned integer
 * TAG_BYTES  = 0x01, TAG_STRING = 0x02, TAG_UINT = 0x03
 * ```
 *
 * Rules:
 * - Only declared bytes, UTF-8 strings and unsigned integers are accepted.
 * - Field order is meaningful: `[a, b]` and `[b, a]` digest differently.
 * - Duplicate field names are rejected.
 * - The protocol version is absorbed into the digest preamble.
 * - A field is fully encoded before it touches the hash state, so an encoding
 *   failure leaves the incremental state unchanged.
 * - Lengths are fixed-width u32be; anything overflowing 32 bits is rejected
 *   instead of wrapping. Integers are u64be; anything above 2^64-1 is rejected.
 *
 * The plain hash interfaces (sha256 etc.) are not modified by this module.
 * @module
 */
import { sha256 } from './sha2.ts';
import { abytes, anumber, concatBytes, utf8ToBytes, type TArg, type TRet } from './utils.ts';

/** Type tag: declared bytes (Uint8Array). */
export const TAG_BYTES = 0x01;
/** Type tag: declared UTF-8 string. */
export const TAG_STRING = 0x02;
/** Type tag: declared unsigned integer (u64be). */
export const TAG_UINT = 0x03;

/** Domain-separation prefix absorbed before any field: "noble-struct-hash" || 0x00. */
const MAGIC: Uint8Array = /* @__PURE__ */ concatBytes(
  utf8ToBytes('noble-struct-hash'),
  Uint8Array.of(0)
);
/** Maximum value of the fixed-width u32 length / version fields. */
const MAX_U32 = 0xffffffff;
/** Maximum value of a declared unsigned integer (u64). */
const MAX_U64 = /* @__PURE__ */ BigInt('0xffffffffffffffff');
const _0n = /* @__PURE__ */ BigInt(0);
/** Default protocol version. */
const DEFAULT_VERSION = 1;

/** A value accepted by the structured protocol. */
export type StructValue = Uint8Array | string | number | bigint;
/** One ordered field: `[name, value]`. */
export type StructField = readonly [string, StructValue];
/** Options for {@link structHash} / {@link StructHasher}. */
export type StructHashOpts = {
  /** Protocol version, absorbed into the digest preamble. Integer in `0..2^32-1`. Default: 1. */
  version?: number;
};

// Fixed-width u32be encoding. Rejects overflow instead of silently wrapping.
function u32be(n: number, title: string): TRet<Uint8Array> {
  anumber(n, title);
  if (n > MAX_U32)
    throw new RangeError(title + 'value ' + n + ' overflows fixed-width u32 encoding');
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

function afieldName(name: unknown): asserts name is string {
  if (typeof name !== 'string')
    throw new TypeError('structhash: field name expected string, got type=' + typeof name);
}

function encodeName(name: string): TRet<Uint8Array> {
  afieldName(name);
  const bytes = utf8ToBytes(name);
  return concatBytes(
    Uint8Array.of(TAG_STRING),
    u32be(bytes.length, 'structhash: name length '),
    bytes
  );
}

/**
 * Encodes a single declared value as `tag || u32be(length) || content`.
 * @param value - Uint8Array (bytes), string (UTF-8) or unsigned integer (number / bigint)
 * @returns The explicit byte encoding of the value.
 * @throws On unsupported types, invalid integers or length overflow.
 */
export function encodeStructValue(value: TArg<StructValue>): TRet<Uint8Array> {
  if (typeof value === 'string') {
    const bytes = utf8ToBytes(value);
    return concatBytes(
      Uint8Array.of(TAG_STRING),
      u32be(bytes.length, 'structhash: string length '),
      bytes
    );
  }
  if (typeof value === 'number' || typeof value === 'bigint') {
    // anumber rejects non-integers, negatives and unsafe integers.
    const v = typeof value === 'number' ? BigInt(anumber(value, 'structhash: uint ')) : value;
    if (v < _0n || v > MAX_U64)
      throw new RangeError('structhash: uint ' + v + ' overflows fixed-width u64 encoding');
    const u64 = new Uint8Array(8);
    new DataView(u64.buffer).setBigUint64(0, v, false);
    return concatBytes(Uint8Array.of(TAG_UINT), u32be(8, 'structhash: uint length '), u64);
  }
  const bytes = abytes(value, undefined, 'structhash: ');
  return concatBytes(
    Uint8Array.of(TAG_BYTES),
    u32be(bytes.length, 'structhash: bytes length '),
    bytes
  );
}

/**
 * Encodes one field as `name || value` (see module docs for the byte layout).
 * @param name - field name, a UTF-8 string
 * @param value - declared field value
 * @returns The explicit byte encoding of the field.
 */
export function encodeStructField(name: string, value: TArg<StructValue>): TRet<Uint8Array> {
  return concatBytes(encodeName(name), encodeStructValue(value));
}

function aversion(opts: StructHashOpts | undefined): number {
  const version = opts !== undefined && opts.version !== undefined ? opts.version : DEFAULT_VERSION;
  // u32be() validates range; call it here so a bad version fails before any state exists.
  u32be(version, 'structhash: version ');
  return version;
}

function encodePreamble(version: number): TRet<Uint8Array> {
  return concatBytes(MAGIC, u32be(version, 'structhash: version '));
}

/**
 * Incremental structured hasher. Absorbs one encoded field at a time;
 * a field that fails to encode is rejected before any state is updated.
 * @example
 * ```ts
 * const h = new StructHasher();
 * h.update('user', 'alice').update('uid', 1);
 * const digest = h.digest();
 * ```
 */
export class StructHasher {
  /** Bytes produced by {@link StructHasher.digest}. Matches SHA-256. */
  readonly outputLen: number = 32;
  /** Protocol version this instance absorbs in its preamble. */
  readonly version: number;
  private h = sha256.create();
  private readonly seen = new Set<string>();
  private finished = false;
  constructor(opts?: StructHashOpts) {
    this.version = aversion(opts);
    this.h.update(encodePreamble(this.version));
  }
  /**
   * Encodes and absorbs one field. Encoding happens fully before the state is
   * touched, so a throwing call leaves the running digest unchanged.
   * @param name - field name; must be unique within this hasher
   * @param value - declared value: bytes, UTF-8 string or unsigned integer
   * @returns The same hasher for chaining.
   * @throws On duplicate names, unsupported types, invalid integers or length overflow.
   */
  update(name: string, value: TArg<StructValue>): this {
    if (this.finished) throw new Error('structhash: update() after digest()');
    afieldName(name);
    if (this.seen.has(name))
      throw new Error('structhash: duplicate field name ' + JSON.stringify(name));
    const encoded = encodeStructField(name, value); // may throw; state untouched so far
    this.seen.add(name);
    this.h.update(encoded);
    return this;
  }
  /**
   * Finalizes and returns the 32-byte digest. The instance cannot absorb more fields afterwards.
   * @returns Digest bytes.
   */
  digest(): TRet<Uint8Array> {
    this.finished = true;
    return this.h.digest();
  }
  /**
   * Finalizes into a caller-provided buffer. The instance cannot absorb more fields afterwards.
   * @param buf - destination buffer of at least {@link StructHasher.outputLen} bytes
   */
  digestInto(buf: TArg<Uint8Array>): void {
    this.finished = true;
    this.h.digestInto(buf);
  }
  /** Creates an independent copy of the current state. */
  clone(): StructHasher {
    const to = new StructHasher({ version: this.version });
    to.h = this.h.clone();
    for (const name of this.seen) to.seen.add(name);
    to.finished = this.finished;
    return to;
  }
  /** Wipes internal state and makes the instance unusable. */
  destroy(): void {
    this.finished = true;
    this.h.destroy();
  }
}

/**
 * Convenience constructor for {@link StructHasher}.
 * @param opts - optional protocol version
 */
export function createStructHasher(opts?: StructHashOpts): TRet<StructHasher> {
  return new StructHasher(opts);
}

/**
 * One-shot structured digest of ordered fields.
 * @param fields - ordered `[name, value]` pairs; order matters, names must be unique
 * @param opts - optional protocol version
 * @returns The 32-byte SHA-256 digest of the explicit field encoding.
 * @example
 * ```ts
 * structHash([['user', 'alice'], ['uid', 1]]);
 * ```
 */
export function structHash(
  fields: TArg<readonly StructField[]>,
  opts?: StructHashOpts
): TRet<Uint8Array> {
  const h = new StructHasher(opts);
  for (const field of fields) {
    if (!Array.isArray(field) || field.length !== 2)
      throw new TypeError('structhash: field expected [name, value] pair');
    h.update(field[0], field[1]);
  }
  return h.digest();
}
