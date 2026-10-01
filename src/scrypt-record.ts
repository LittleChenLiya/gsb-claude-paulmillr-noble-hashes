/**
 * Self-contained scrypt password records.
 *
 * A record packs the scrypt cost parameters, salt and derived hash into a
 * single text string that can be stored and later re-verified:
 *
 *   $scrypt$ln=14,r=8,p=1$c2FsdA$aGFzaA
 *
 * - "ln" is the log2 of the scrypt work factor N (N = 2**ln)
 * - "r" and "p" are the scrypt block size and parallelization parameters
 * - salt and hash are standard Base64 (RFC 4648 section 4) without padding
 *
 * The field order is fixed (ln, r, p, salt, hash). Parsing is strict:
 * duplicated parameters, leading "+" signs, leading zeros, whitespace,
 * padded or invalid Base64, out-of-range integers and records that exceed
 * the memory budget are all rejected before any scrypt computation happens.
 * @module
 */
import { scrypt, type ScryptOpts } from './scrypt.ts';
// prettier-ignore
import {
  abytes,
  clean,
  copyBytes,
  randomBytes,
  type KDFInput,
  type TArg,
  type TRet
} from './utils.ts';

/** Scrypt cost parameters encoded in a record. */
export type ScryptRecordParams = {
  /** Log2 of the scrypt work factor: N = 2**ln. */
  ln: number;
  /** Scrypt block size parameter. */
  r: number;
  /** Scrypt parallelization parameter. */
  p: number;
};

/** A parsed scrypt record: cost parameters, salt and expected hash. */
export type ParsedScryptRecord = {
  params: ScryptRecordParams;
  salt: Uint8Array;
  hash: Uint8Array;
};

/** Options for {@link createScryptRecord}. */
export type ScryptRecordCreateOpts = ScryptRecordParams & {
  /** Salt bytes. Random 16 bytes when omitted. Copied before use. */
  salt?: Uint8Array;
  /** Derived hash length in bytes. Default: 32. */
  dkLen?: number;
  /** Maximum temporary memory budget in bytes. Default: 1 GiB + 2 KiB. */
  maxmem?: number;
};

/** Injectable scrypt function, matches the sync {@link scrypt} signature. */
export type ScryptFn = (
  password: TArg<KDFInput>,
  salt: TArg<KDFInput>,
  opts: ScryptOpts
) => TRet<Uint8Array>;

/** Options for {@link parseScryptRecord} and {@link verifyScryptRecord}. */
export type ScryptRecordReadOpts = {
  /** Maximum temporary memory budget in bytes. Default: 1 GiB + 2 KiB. */
  maxmem?: number;
  /**
   * Scrypt implementation to use for verification. Defaults to the real
   * {@link scrypt}; mainly useful to inject instrumented test doubles.
   */
  scryptImpl?: ScryptFn;
};

// Same budget as scrypt own default: 128*8*(2**20+1+1) = 1 GiB + 2 KiB.
const RECORD_DEFAULT_MAXMEM = 128 * 8 * (2 ** 20 + 1 + 1);
const POW32 = 2 ** 32;
const MAX_LN = 32; // scrypt caps N at 2**32
const DEFAULT_SALT_LEN = 16;
const DEFAULT_DK_LEN = 32;

const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_LOOKUP: Int16Array = /* @__PURE__ */ (() => {
  const table = new Int16Array(128).fill(-1);
  for (let i = 0; i < B64_ALPHABET.length; i++) table[B64_ALPHABET.charCodeAt(i)] = i;
  return table;
})();

/** Standard Base64 (RFC 4648 section 4) without padding. */
function base64Encode(bytes: TArg<Uint8Array>): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += B64_ALPHABET[b0 >> 2] + B64_ALPHABET[((b0 & 3) << 4) | (b1 >> 4)];
    if (i + 1 < bytes.length) out += B64_ALPHABET[((b1 & 15) << 2) | (b2 >> 6)];
    if (i + 2 < bytes.length) out += B64_ALPHABET[b2 & 63];
  }
  return out;
}

/** Strict decoder for unpadded standard Base64. Rejects '=' and non-alphabet chars. */
function base64Decode(str: string, title: string): Uint8Array {
  if (str.length === 0) throw new Error('scrypt record: ' + title + ' must not be empty');
  // Unpadded base64 can never have a length congruent to 1 mod 4.
  if (str.length % 4 === 1)
    throw new Error('scrypt record: ' + title + ' has invalid base64 length');
  const fullGroups = Math.floor(str.length / 4);
  const rem = str.length % 4;
  const out = new Uint8Array(fullGroups * 3 + (rem === 0 ? 0 : rem - 1));
  const sextet = (idx: number): number => {
    const code = str.charCodeAt(idx);
    const value = code < 128 ? B64_LOOKUP[code] : -1;
    if (value === -1)
      throw new Error('scrypt record: ' + title + ' contains invalid base64 character');
    return value;
  };
  let pos = 0;
  for (let i = 0; i < str.length; i += 4) {
    const left = Math.min(4, str.length - i);
    const s0 = sextet(i);
    const s1 = sextet(i + 1);
    out[pos++] = (s0 << 2) | (s1 >> 4);
    if (left > 2) {
      const s2 = sextet(i + 2);
      out[pos++] = ((s1 & 15) << 4) | (s2 >> 2);
      if (left > 3) out[pos++] = ((s2 & 3) << 6) | sextet(i + 3);
    }
  }
  return out;
}

// Canonical non-negative decimal integer: digits only, no "+", no spaces,
// no leading zeros, and exactly representable as a JS safe integer.
function parseDecimal(text: string, name: string): number {
  if (!/^[0-9]+$/.test(text))
    throw new Error('scrypt record: "' + name + '" must be a non-negative decimal integer');
  const value = Number(text);
  if (!Number.isSafeInteger(value))
    throw new Error('scrypt record: "' + name + '" overflows the safe integer range');
  if (String(value) !== text)
    throw new Error('scrypt record: "' + name + '" must be in canonical decimal form');
  return value;
}

// Mirrors the range checks in scryptInit so that invalid records are
// rejected here, before any scrypt computation is invoked.
function validateParams(params: ScryptRecordParams, maxmem: number): void {
  const { ln, r, p } = params;
  if (ln < 1 || ln > MAX_LN)
    throw new Error('scrypt record: "ln" expected integer 1..' + MAX_LN + ', got ' + ln);
  if (r < 1) throw new Error('scrypt record: "r" expected integer >= 1');
  if (p < 1 || p > ((POW32 - 1) * 32) / (128 * r))
    throw new Error('scrypt record: "p" expected integer 1..((2^32 - 1) * 32) / (128 * r)');
  const memUsed = 128 * r * (2 ** ln + p + 1);
  if (memUsed > maxmem)
    throw new Error(
      'scrypt record: "maxmem" limit was hit: memUsed(128*r*(2**ln+p+1))=' +
        memUsed +
        ', maxmem=' +
        maxmem
    );
}

function timingSafeEqual(a: TArg<Uint8Array>, b: TArg<Uint8Array>): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Parses a scrypt record string into its parameters, salt and hash.
 * Fully validates the record (format, parameter ranges, memory budget)
 * without running scrypt, so a rejected record never reaches the KDF.
 * @param record - text in the form "$scrypt$ln=N,r=R,p=P$salt$hash"
 * @param opts - see {@link ScryptRecordReadOpts} ("scryptImpl" is ignored here)
 * @returns Parsed parameters, salt and hash. The returned arrays are fresh copies.
 * @throws If the record is malformed or out of budget. {@link Error}
 */
export function parseScryptRecord(
  record: string,
  opts: ScryptRecordReadOpts = {}
): ParsedScryptRecord {
  if (typeof record !== 'string') throw new Error('scrypt record: expected a string');
  const maxmem = opts.maxmem === undefined ? RECORD_DEFAULT_MAXMEM : opts.maxmem;
  if (!Number.isSafeInteger(maxmem) || maxmem < 0)
    throw new Error('scrypt record: "maxmem" must be a non-negative safe integer');
  const parts = record.split('$');
  if (parts.length !== 5 || parts[0] !== '' || parts[1] !== 'scrypt')
    throw new Error('scrypt record: expected "$scrypt$ln=N,r=R,p=P$salt$hash"');
  const fields = parts[2].split(',');
  if (fields.length !== 3) throw new Error('scrypt record: expected exactly 3 parameters "ln,r,p"');
  const names = ['ln', 'r', 'p'];
  const seen = new Set<string>();
  const values: number[] = [];
  for (let i = 0; i < fields.length; i++) {
    const kv = fields[i].split('=');
    if (kv.length !== 2 || kv[0] === '' || kv[1] === '')
      throw new Error('scrypt record: malformed parameter "' + fields[i] + '"');
    const [name, raw] = kv;
    if (seen.has(name)) throw new Error('scrypt record: duplicate parameter "' + name + '"');
    seen.add(name);
    if (name !== names[i])
      throw new Error(
        'scrypt record: parameter "' + name + '" out of order, expected "' + names[i] + '"'
      );
    values.push(parseDecimal(raw, name));
  }
  const params: ScryptRecordParams = { ln: values[0], r: values[1], p: values[2] };
  validateParams(params, maxmem);
  const salt = base64Decode(parts[3], 'salt');
  const hash = base64Decode(parts[4], 'hash');
  return { params, salt, hash };
}

/**
 * Creates a scrypt record string for a password.
 * @param password - password or key material; JS strings are UTF-8 encoded first
 * @param opts - cost parameters plus optional salt / dkLen / maxmem.
 *   See {@link ScryptRecordCreateOpts}.
 * @returns Record text in the form "$scrypt$ln=N,r=R,p=P$salt$hash"
 * @throws If the parameters are invalid or exceed the memory budget. {@link Error}
 * @example
 * const record = createScryptRecord('correct horse', { ln: 15, r: 8, p: 1 });
 */
export function createScryptRecord(password: TArg<KDFInput>, opts: ScryptRecordCreateOpts): string {
  const { ln, r, p } = opts;
  const dkLen = opts.dkLen === undefined ? DEFAULT_DK_LEN : opts.dkLen;
  const maxmem = opts.maxmem === undefined ? RECORD_DEFAULT_MAXMEM : opts.maxmem;
  if (!Number.isSafeInteger(ln) || !Number.isSafeInteger(r) || !Number.isSafeInteger(p))
    throw new Error('scrypt record: "ln", "r" and "p" must be safe integers');
  if (!Number.isSafeInteger(dkLen) || dkLen < 1 || dkLen > (POW32 - 1) * 32)
    throw new Error('scrypt record: "dkLen" expected integer 1..(2^32 - 1) * 32');
  validateParams({ ln, r, p }, maxmem);
  let salt: Uint8Array;
  if (opts.salt === undefined) {
    salt = randomBytes(DEFAULT_SALT_LEN);
  } else {
    abytes(opts.salt, undefined, 'salt');
    if (opts.salt.length === 0) throw new Error('scrypt record: "salt" must not be empty');
    salt = copyBytes(opts.salt); // never mutate or alias caller memory
  }
  const hash = scrypt(password, salt, { N: 2 ** ln, r, p, dkLen, maxmem });
  return (
    '$scrypt$ln=' + ln + ',r=' + r + ',p=' + p + '$' + base64Encode(salt) + '$' + base64Encode(hash)
  );
}

/**
 * Verifies a password against a scrypt record string.
 * The record is fully parsed and validated first; malformed or over-budget
 * records throw before any scrypt computation happens.
 * @param record - text produced by {@link createScryptRecord}
 * @param password - candidate password or key material
 * @param opts - see {@link ScryptRecordReadOpts}
 * @returns "true" when the password matches, "false" otherwise
 * @throws If the record is malformed or out of budget. {@link Error}
 */
export function verifyScryptRecord(
  record: string,
  password: TArg<KDFInput>,
  opts: ScryptRecordReadOpts = {}
): boolean {
  const maxmem = opts.maxmem === undefined ? RECORD_DEFAULT_MAXMEM : opts.maxmem;
  const { params, salt, hash } = parseScryptRecord(record, { maxmem });
  const scryptFn = opts.scryptImpl === undefined ? scrypt : opts.scryptImpl;
  // Copy the salt so the parsed record arrays are never mutated by the KDF.
  const derived = scryptFn(password, copyBytes(salt), {
    N: 2 ** params.ln,
    r: params.r,
    p: params.p,
    dkLen: hash.length,
    maxmem,
  });
  try {
    return timingSafeEqual(derived, hash);
  } finally {
    clean(derived);
  }
}
