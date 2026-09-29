/**
 * Scrypt password records: self-contained "$scrypt$ln=N,r=R,p=P$salt$hash" strings
 * that bundle the scrypt cost parameters, salt and digest, so a password can be
 * re-verified later without out-of-band parameter storage.
 *
 * Format rules (strict, canonical):
 * - fields are fixed-order: "ln", "r", "p", then salt, then hash
 * - "ln" is the log2 of the scrypt work factor: N = 2**ln
 * - numbers are decimal without leading zeros, leading "+" or whitespace
 * - salt and hash are standard Base64 (RFC 4648 section 4) without padding
 * - duplicate, reordered, missing or unknown parameters are rejected
 * @module
 */
import { scrypt, type ScryptOpts } from './scrypt.ts';
// prettier-ignore
import {
  abytes, anumber, randomBytes, validateObject,
  type KDFInput, type TArg, type TRet
} from './utils.ts';

// Same default budget as scrypt itself: 128*r*(N+p+1) for N=2**20, r=8, p=1.
const SCRYPT_RECORD_DEFAULT_MAXMEM = 128 * 8 * (2 ** 20 + 1 + 1);

// scrypt caps N at 2**32, so ln fits in 1..32.
const MAX_LN = 32;

const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/** Encodes bytes as standard Base64 without padding. */
function bytesToBase64(bytes: TArg<Uint8Array>): string {
  abytes(bytes);
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const chunk = ((bytes[i] << 16) | ((bytes[i + 1] || 0) << 8) | (bytes[i + 2] || 0)) >>> 0;
    out += B64_ALPHABET[(chunk >> 18) & 63] + B64_ALPHABET[(chunk >> 12) & 63];
    if (i + 1 < bytes.length) out += B64_ALPHABET[(chunk >> 6) & 63];
    if (i + 2 < bytes.length) out += B64_ALPHABET[chunk & 63];
  }
  return out;
}

/**
 * Decodes standard Base64 without padding, rejecting anything non-canonical:
 * padding characters, characters outside the alphabet, impossible lengths and
 * non-zero trailing bits.
 */
function base64ToBytes(str: string, title: string): TRet<Uint8Array> {
  if (!/^[A-Za-z0-9+/]+$/.test(str))
    throw new Error('"' + title + '" expected unpadded standard Base64');
  // A Base64 length of 1 (mod 4) cannot encode a whole number of bytes.
  if (str.length % 4 === 1)
    throw new Error('"' + title + '" has invalid Base64 length: ' + str.length);
  const codes: number[] = [];
  for (let i = 0; i < str.length; i++) codes.push(B64_ALPHABET.indexOf(str[i]));
  const out: number[] = [];
  for (let i = 0; i < codes.length; i += 4) {
    const chunk =
      ((codes[i] << 18) |
        ((codes[i + 1] || 0) << 12) |
        ((codes[i + 2] || 0) << 6) |
        (codes[i + 3] || 0)) >>>
      0;
    out.push((chunk >> 16) & 255);
    if (i + 2 < codes.length) out.push((chunk >> 8) & 255);
    if (i + 3 < codes.length) out.push(chunk & 255);
  }
  const bytes = new Uint8Array(out);
  // Round-trip check rejects non-canonical encodings (non-zero trailing bits).
  if (bytesToBase64(bytes) !== str) throw new Error('"' + title + '" is not canonical Base64');
  return bytes as TRet<Uint8Array>;
}

// Fixed field order, no duplicates, no leading zeros/plus signs, no whitespace.
const RECORD_RE =
  /^\$scrypt\$ln=(0|[1-9][0-9]*),r=(0|[1-9][0-9]*),p=(0|[1-9][0-9]*)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/;

// Shared range checks for parsed and freshly-created records.
function checkRecordParams(ln: number, r: number, p: number): void {
  anumber(ln, 'ln');
  anumber(r, 'r');
  anumber(p, 'p');
  if (ln < 1 || ln > MAX_LN) throw new Error('"ln" expected integer 1..' + MAX_LN);
  if (r < 1) throw new Error('"r" expected integer >= 1');
  // Same bound as scrypt: p <= (2^32 - 1) * 32 / (128 * r).
  const maxP = Math.floor(((2 ** 32 - 1) * 32) / (128 * r));
  if (p < 1 || p > maxP) throw new Error('"p" expected integer 1..' + maxP);
}

/** Temporary memory scrypt needs for the given record parameters, in bytes. */
function recordMemory(ln: number, r: number, p: number): number {
  return 128 * r * (2 ** ln + p + 1);
}

function equalBytes(a: TArg<Uint8Array>, b: TArg<Uint8Array>): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Parsed scrypt password record. See {@link parseScryptRecord}.
 */
export type ScryptRecord = {
  /** Log2 of the scrypt work factor: N = 2**ln. */
  ln: number;
  /** Block size parameter. */
  r: number;
  /** Parallelization parameter. */
  p: number;
  /** Salt bytes. */
  salt: Uint8Array;
  /** Derived key bytes (the password digest). */
  hash: Uint8Array;
};

/**
 * Parses a "$scrypt$ln=N,r=R,p=P$salt$hash" record into its components.
 * The grammar is strict: fixed field order, canonical decimal numbers and
 * canonical unpadded standard Base64 for salt and hash.
 * @param record - record string to parse
 * @returns Parsed parameters, salt and hash.
 * @throws If the record is malformed or out of range. {@link Error}
 * @example
 * const { ln, r, p, salt, hash } = parseScryptRecord(record);
 */
export function parseScryptRecord(record: string): ScryptRecord {
  if (typeof record !== 'string')
    throw new TypeError('scrypt record expected string, got ' + typeof record);
  const m = RECORD_RE.exec(record);
  if (m === null)
    throw new Error('invalid scrypt record: expected "$scrypt$ln=<n>,r=<n>,p=<n>$<salt>$<hash>"');
  const ln = Number(m[1]);
  const r = Number(m[2]);
  const p = Number(m[3]);
  checkRecordParams(ln, r, p);
  const salt = base64ToBytes(m[4], 'salt');
  const hash = base64ToBytes(m[5], 'hash');
  return { ln, r, p, salt, hash };
}

/**
 * Options for {@link createScryptRecord}.
 */
export type CreateScryptRecordOpts = {
  /** Log2 of the scrypt work factor: N = 2**ln. Integer 1..32. */
  ln: number;
  /** Block size parameter. */
  r: number;
  /** Parallelization parameter. */
  p: number;
  /** Salt bytes; random 16 bytes when omitted. Must be non-empty. */
  salt?: Uint8Array;
  /** Digest length in bytes, default 32. */
  dkLen?: number;
  /** Maximum temporary memory budget in bytes, forwarded to scrypt. */
  maxmem?: number;
};

/**
 * Creates a scrypt password record string for a password.
 * @param password - password or key material; JS strings are UTF-8 encoded first
 * @param opts - record parameters. See {@link CreateScryptRecordOpts}.
 * @returns Record string "$scrypt$ln=N,r=R,p=P$salt$hash".
 * @throws If the parameters are invalid. {@link Error}
 * @example
 * const record = createScryptRecord('correct horse', { ln: 15, r: 8, p: 1 });
 */
export function createScryptRecord(password: TArg<KDFInput>, opts: CreateScryptRecordOpts): string {
  validateObject(
    opts as Record<string, any>,
    { ln: 'number', r: 'number', p: 'number' },
    { salt: 'object', dkLen: 'number', maxmem: 'number' },
    'createScryptRecord'
  );
  const { ln, r, p, salt = randomBytes(16), dkLen = 32, maxmem } = opts;
  checkRecordParams(ln, r, p);
  abytes(salt, undefined, 'salt');
  if (salt.length < 1) throw new Error('"salt" expected non-empty byte array');
  anumber(dkLen, 'dkLen');
  if (dkLen < 1) throw new Error('"dkLen" expected integer >= 1');
  const scryptOpts: ScryptOpts = { N: 2 ** ln, r, p, dkLen };
  if (maxmem !== undefined) scryptOpts.maxmem = maxmem;
  const hash = scrypt(password, salt, scryptOpts);
  return (
    '$scrypt$ln=' +
    ln +
    ',r=' +
    r +
    ',p=' +
    p +
    '$' +
    bytesToBase64(salt) +
    '$' +
    bytesToBase64(hash)
  );
}

/**
 * Options for {@link verifyScryptRecord}.
 */
export type VerifyScryptRecordOpts = {
  /**
   * Maximum temporary memory budget in bytes. Records needing more are
   * rejected before any scrypt computation happens.
   * Default: 1 GiB + 2 KiB (same as scrypt itself).
   */
  maxmem?: number;
  /**
   * scrypt implementation to use, defaults to the real one.
   * Testing hook: lets callers prove malformed records never reach scrypt.
   */
  scryptFn?: (password: TArg<KDFInput>, salt: Uint8Array, opts: ScryptOpts) => Uint8Array;
};

/**
 * Verifies a password against a scrypt password record string.
 * Never throws on malformed records: any parse, range or memory-budget
 * failure returns "false" before scrypt is invoked.
 * @param password - password to check; JS strings are UTF-8 encoded first
 * @param record - record string produced by {@link createScryptRecord}
 * @param opts - verification options. See {@link VerifyScryptRecordOpts}.
 * @returns "true" when the password matches the record digest.
 * @example
 * verifyScryptRecord('correct horse', record); // true
 * verifyScryptRecord('wrong', record); // false
 */
export function verifyScryptRecord(
  password: TArg<KDFInput>,
  record: string,
  opts: VerifyScryptRecordOpts = {}
): boolean {
  try {
    validateObject(
      opts as Record<string, any>,
      {},
      { maxmem: 'number', scryptFn: 'function' },
      'verifyScryptRecord'
    );
    const { maxmem = SCRYPT_RECORD_DEFAULT_MAXMEM, scryptFn = scrypt } = opts;
    anumber(maxmem, 'maxmem');
    const { ln, r, p, salt, hash } = parseScryptRecord(record);
    // Enforce the memory budget here so over-budget records never reach scrypt.
    if (recordMemory(ln, r, p) > maxmem) return false;
    const expected = scryptFn(password, salt, { N: 2 ** ln, r, p, dkLen: hash.length, maxmem });
    return equalBytes(expected, hash);
  } catch {
    return false;
  }
}
