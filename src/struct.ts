/**
 * Explicit structured digest protocol built on top of SHA-256.
 *
 * Each field is encoded as a self-describing record: a fixed-width name
 * length, the UTF-8 field name, a one-byte type tag, a fixed-width value
 * length, and the value bytes. The type tag and fixed-width lengths make
 * the encoding unambiguous: two fields with adjacent values cannot be
 * confused with a single field, and a string "1" cannot collide with the
 * integer 1. Field order is preserved by hashing records in sequence, and
 * duplicate field names are rejected. The protocol version is hashed first
 * so future revisions are domain-separated.
 *
 * Encoding is performed into a temporary buffer before the hash state is
 * touched, so a failed field never updates the incremental state.
 * @module
 */
import { sha256 } from "./sha2.ts";
import { abytes, anumber, createView, isBytes, utf8ToBytes } from "./utils.ts";

/** Protocol version byte, hashed before any field record. */
export const STRUCT_VERSION = 0x01;

/** Type tag for raw byte arrays. */
export const TAG_BYTES = 0x01;
/** Type tag for UTF-8 strings. */
export const TAG_STRING = 0x02;
/** Type tag for unsigned integers. */
export const TAG_UINT = 0x03;

/** Fixed-width byte width of the field name length prefix. */
const NAME_LEN_WIDTH = 2;
/** Fixed-width byte width of the field value length prefix. */
const VALUE_LEN_WIDTH = 4;

/** A field value accepted by the structured digest protocol. */
export type StructValue = Uint8Array | string | number | bigint;

/** Declared field type. */
export type StructType = "bytes" | "string" | "uint";

/** A single named field record. */
export interface StructField {
  /** Field name; must be unique within a digest. */
  name: string;
  /** Declared value type. */
  type: StructType;
  /** Field value matching the declared type. */
  value: StructValue;
}

/**
 * Encodes a non-negative integer as minimal big-endian bytes.
 * Zero encodes as a single 0x00 byte; positive integers have no leading
 * zero bytes, so the representation is canonical.
 * @param value - non-negative integer
 * @returns Minimal big-endian byte representation.
 * @throws On negative, non-integer, or non-numeric input.
 */
function uintToBytes(value: number | bigint): Uint8Array {
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0)
      throw new RangeError("uint field requires non-negative integer, got " + value);
    if (value === 0) return new Uint8Array([0]);
    const bytes: number[] = [];
    let v = value;
    while (v > 0) {
      bytes.push(v & 0xff);
      v = Math.floor(v / 256);
    }
    return new Uint8Array(bytes.reverse());
  }
  if (typeof value === "bigint") {
    if (value < 0n) throw new RangeError("uint field requires non-negative integer, got " + value);
    if (value === 0n) return new Uint8Array([0]);
    const bytes: number[] = [];
    let v = value;
    while (v > 0n) {
      bytes.push(Number(v & 0xffn));
      v >>= 8n;
    }
    return new Uint8Array(bytes.reverse());
  }
  throw new TypeError("uint field requires number or bigint, got " + typeof value);
}

/**
 * Encodes a single field record into a self-describing byte buffer.
 *
 * Layout (all multi-byte integers are big-endian):
 * <pre>
 * name_len : u16
 * name     : UTF-8 bytes
 * type     : u8  (0x01 bytes, 0x02 string, 0x03 uint)
 * value_len: u32
 * value    : bytes
 * </pre>
 * @param name - field name
 * @param type - declared value type
 * @param value - field value
 * @returns Encoded field record.
 * @throws On invalid name, type, value, or length overflow.
 */
export function encodeField(name: string, type: StructType, value: StructValue): Uint8Array {
  if (typeof name !== "string") throw new TypeError("field name must be a string, got " + typeof name);
  const nameBytes = utf8ToBytes(name);
  if (nameBytes.length > 0xffff)
    throw new RangeError("field name too long: " + nameBytes.length + " > 65535");

  let tag: number;
  let valueBytes: Uint8Array;
  if (type === "bytes") {
    tag = TAG_BYTES;
    if (!isBytes(value))
      throw new TypeError("bytes field requires Uint8Array, got " + typeof value);
    valueBytes = abytes(value, undefined, "bytes field");
  } else if (type === "string") {
    tag = TAG_STRING;
    if (typeof value !== "string")
      throw new TypeError("string field requires string value, got " + typeof value);
    valueBytes = utf8ToBytes(value);
  } else if (type === "uint") {
    tag = TAG_UINT;
    if (typeof value !== "number" && typeof value !== "bigint")
      throw new TypeError("uint field requires number or bigint, got " + typeof value);
    valueBytes = uintToBytes(value);
  } else {
    throw new TypeError("unknown field type: " + String(type));
  }

  if (valueBytes.length > 0xffffffff)
    throw new RangeError("field value too long: " + valueBytes.length + " > 4294967295");

  const total = NAME_LEN_WIDTH + nameBytes.length + 1 + VALUE_LEN_WIDTH + valueBytes.length;
  const out = new Uint8Array(total);
  const view = createView(out);
  let offset = 0;
  view.setUint16(offset, nameBytes.length, false);
  offset += NAME_LEN_WIDTH;
  out.set(nameBytes, offset);
  offset += nameBytes.length;
  view.setUint8(offset, tag);
  offset += 1;
  view.setUint32(offset, valueBytes.length, false);
  offset += VALUE_LEN_WIDTH;
  out.set(valueBytes, offset);
  return out;
}

/** Incremental structured digest hasher. */
export interface StructHasher {
  /**
   * Adds a field record to the digest.
   *
   * The field is fully encoded and validated before the hash state is
   * updated, so a failed call leaves the state (and the seen-name set)
   * unchanged.
   * @param name - field name
   * @param type - declared value type
   * @param value - field value
   * @returns The same hasher for chaining.
   * @throws On invalid field or duplicate name.
   */
  field(name: string, type: StructType, value: StructValue): this;
  /**
   * Finalizes the digest and returns the 32-byte hash.
   * @returns Digest bytes.
   * @throws If called more than once.
   */
  digest(): Uint8Array;
}

/**
 * Creates an incremental structured digest hasher using SHA-256.
 *
 * The protocol version is absorbed immediately. Fields are then added one
 * at a time; each is encoded into a temporary buffer first, so encoding
 * failures never update the incremental state.
 * @returns A new structured hasher.
 */
export function createStructHasher(): StructHasher {
  const hash = sha256.create();
  hash.update(new Uint8Array([STRUCT_VERSION]));
  const seen = new Set<string>();
  let finished = false;
  return {
    field(name, type, value) {
      if (finished) throw new Error("digest() was already called");
      // Encode first: this performs all validation. Only after it succeeds do
      // we touch the hash state or the seen-name set.
      const encoded = encodeField(name, type, value);
      if (seen.has(name)) throw new Error("duplicate field name: " + name);
      hash.update(encoded);
      seen.add(name);
      return this;
    },
    digest() {
      if (finished) throw new Error("digest() was already called");
      finished = true;
      return hash.digest();
    },
  };
}

/**
 * Computes a structured digest over an ordered list of fields.
 *
 * Field order is meaningful and duplicate names are rejected. The protocol
 * version is included in the digest.
 * @param fields - ordered field records
 * @returns 32-byte digest.
 * @throws On invalid field or duplicate name.
 */
export function structDigest(fields: StructField[]): Uint8Array {
  anumber(fields.length, "fields.length");
  const h = createStructHasher();
  for (const f of fields) h.field(f.name, f.type, f.value);
  return h.digest();
}
