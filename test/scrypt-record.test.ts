import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, strictEqual as eq, throws } from 'node:assert';
import { scrypt } from '../src/scrypt.ts';
import { createScryptRecord, parseScryptRecord, verifyScryptRecord } from '../src/scrypt-record.ts';
import { hexToBytes } from '../src/utils.ts';

const SALT = hexToBytes('000102030405060708090a0b0c0d0e0f');
const PARAMS = { ln: 14, r: 8, p: 1 };
const PASSWORD = 'correct horse battery staple';

// Counting scrypt stand-in: proves invalid records never reach scrypt.
function countingScrypt(real = false) {
  const stub = { calls: 0 };
  const fn = (password, salt, opts) => {
    stub.calls++;
    if (!real) throw new Error('scrypt must not be called');
    return scrypt(password, salt, opts);
  };
  return { stub, fn };
}

describe('scrypt-record', () => {
  it('creates a record with fixed salt and verifies passwords', () => {
    const record = createScryptRecord(PASSWORD, { ...PARAMS, salt: SALT });
    eq(record.startsWith('$scrypt$ln=14,r=8,p=1$'), true);
    eq(record.split('$').length, 5);
    // No padding in the Base64 fields
    const parts = record.split('$');
    eq(parts[3].includes('='), false);
    eq(parts[4].includes('='), false);
    eq(verifyScryptRecord(PASSWORD, record), true);
    eq(verifyScryptRecord('wrong password', record), false);
    eq(verifyScryptRecord(PASSWORD + ' ', record), false);
    eq(verifyScryptRecord('', record), false);
  });

  it('round-trips: parsed params match the original ones', () => {
    const record = createScryptRecord(PASSWORD, { ...PARAMS, salt: SALT, dkLen: 48 });
    const parsed = parseScryptRecord(record);
    eql(parsed.ln, PARAMS.ln);
    eql(parsed.r, PARAMS.r);
    eql(parsed.p, PARAMS.p);
    eql(parsed.salt, SALT);
    // Hash matches a direct scrypt call with the same parameters
    const expected = scrypt(PASSWORD, SALT, { N: 2 ** PARAMS.ln, r: 8, p: 1, dkLen: 48 });
    eql(parsed.hash, expected);
    // Re-parsing is stable
    eql(parseScryptRecord(record), parsed);
  });

  it('generates a random salt by default', () => {
    const a = createScryptRecord(PASSWORD, PARAMS);
    const b = createScryptRecord(PASSWORD, PARAMS);
    eq(a !== b, true);
    eql(parseScryptRecord(a).salt.length, 16);
    eq(verifyScryptRecord(PASSWORD, a), true);
    eq(verifyScryptRecord(PASSWORD, b), true);
  });

  it('rejects malformed records in parse and verify', () => {
    const valid = createScryptRecord(PASSWORD, { ...PARAMS, salt: SALT });
    const [head, saltB64, hashB64] = [
      valid.slice(0, valid.indexOf('$', 8)),
      valid.split('$')[3],
      valid.split('$')[4],
    ];
    const invalid = [
      '', // empty
      'not-a-record',
      valid.slice(1), // missing leading $
      valid + ' ', // trailing whitespace
      ' ' + valid, // leading whitespace
      valid.replace('ln=14', 'ln=+14'), // leading plus sign
      valid.replace('ln=14', 'ln=014'), // leading zero
      valid.replace('ln=14', 'ln='), // empty number
      valid.replace('ln=14', 'ln=14.0'), // non-integer
      valid.replace('ln=14', 'ln= 14'), // inner whitespace
      valid.replace(',r=8', ', r=8'), // whitespace after comma
      valid.replace('ln=14,r=8,p=1', 'r=8,ln=14,p=1'), // reordered fields
      valid.replace('ln=14,r=8,p=1', 'ln=14,ln=14,r=8,p=1'), // duplicate ln
      valid.replace('ln=14,r=8,p=1', 'ln=14,r=8,r=8,p=1'), // duplicate r
      valid.replace('ln=14,r=8,p=1', 'ln=14,r=8,p=1,p=1'), // duplicate p
      valid.replace('ln=14,r=8,p=1', 'ln=14,r=8'), // missing p
      valid.replace('ln=14,r=8,p=1', 'ln=14,r=8,p=1,x=2'), // unknown field
      valid.replace('ln=14', 'ln=0'), // ln too small
      valid.replace('ln=14', 'ln=33'), // ln too large (N > 2^32)
      valid.replace('ln=14', 'ln=99999999999999999999999999'), // ln integer overflow
      valid.replace('r=8', 'r=0'), // r too small
      valid.replace('r=8', 'r=9007199254740993'), // r above max safe integer
      valid.replace('p=1', 'p=0'), // p too small
      valid.replace('p=1', 'p=9007199254740993'), // p above max safe integer
      valid.replace('p=1', 'p=134217728'), // p above scrypt bound for r=8
      head + '$' + saltB64 + '=' + '$' + hashB64, // padded Base64 salt
      head + '$' + saltB64.slice(0, -1) + '!$' + hashB64, // invalid Base64 char
      head + '$A$' + hashB64, // Base64 length 1 mod 4
      head + '$AB$' + hashB64, // non-canonical Base64 (trailing bits)
      head + '$$' + hashB64, // empty salt
      head + '$' + saltB64 + '$', // empty hash
      head + '$' + hashB64 + '=', // missing hash field
    ];
    for (const bad of invalid) {
      throws(() => parseScryptRecord(bad), 'parse: ' + JSON.stringify(bad));
      eq(verifyScryptRecord(PASSWORD, bad), false, 'verify: ' + JSON.stringify(bad));
    }
    // Non-string input
    throws(() => parseScryptRecord(42));
    eq(verifyScryptRecord(PASSWORD, 42), false);
    eq(verifyScryptRecord(PASSWORD, null), false);
    eq(verifyScryptRecord(PASSWORD, undefined), false);
  });

  it('proves invalid records never reach scrypt (counting stub)', () => {
    const { stub, fn } = countingScrypt();
    const valid = createScryptRecord(PASSWORD, { ...PARAMS, salt: SALT });
    const invalid = [
      valid.replace('ln=14', 'ln=33'), // huge ln
      valid.replace('ln=14', 'ln=+14'),
      valid.replace('ln=14,r=8,p=1', 'ln=14,ln=14,r=8,p=1'),
      valid.replace('r=8', 'r=9007199254740993'),
      valid.replace('$' + valid.split('$')[3] + '$', '$!!!!$'),
      valid.slice(0, -1), // truncated hash
    ];
    for (const bad of invalid) eq(verifyScryptRecord(PASSWORD, bad, { scryptFn: fn }), false);
    eql(stub.calls, 0);
    // Memory budget exceeded: rejected before scrypt
    const memUsed = 128 * 8 * (2 ** 14 + 1 + 1);
    eq(verifyScryptRecord(PASSWORD, valid, { maxmem: memUsed - 1, scryptFn: fn }), false);
    eql(stub.calls, 0);
  });

  it('enforces the memory budget boundary exactly', () => {
    const { stub, fn } = countingScrypt(true);
    const record = createScryptRecord(PASSWORD, { ...PARAMS, salt: SALT });
    const memUsed = 128 * 8 * (2 ** 14 + 1 + 1);
    // Exact budget: allowed, scrypt runs once
    eq(verifyScryptRecord(PASSWORD, record, { maxmem: memUsed, scryptFn: fn }), true);
    eql(stub.calls, 1);
    // One byte under: rejected without calling scrypt
    eq(verifyScryptRecord(PASSWORD, record, { maxmem: memUsed - 1, scryptFn: fn }), false);
    eql(stub.calls, 1);
    // Default budget covers default-sized records
    eq(verifyScryptRecord(PASSWORD, record, { scryptFn: fn }), true);
    eql(stub.calls, 2);
  });

  it('rejects oversized ln via memory budget before scrypt', () => {
    const { stub, fn } = countingScrypt();
    // ln=32 is structurally valid but needs ~512 GiB with r=8
    const record = '$scrypt$ln=32,r=8,p=1$' + validSaltHash();
    eq(verifyScryptRecord(PASSWORD, record, { scryptFn: fn }), false);
    eql(stub.calls, 0);
  });

  it('does not mutate caller arrays', () => {
    const password = new Uint8Array([1, 2, 3, 4, 5]);
    const salt = new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2]);
    const passwordCopy = password.slice();
    const saltCopy = salt.slice();
    const opts = { ...PARAMS, salt };
    const record = createScryptRecord(password, opts);
    eql(password, passwordCopy);
    eql(salt, saltCopy);
    verifyScryptRecord(password, record);
    eql(password, passwordCopy);
    eql(salt, saltCopy);
    // Options object is not mutated either
    eql(opts, { ...PARAMS, salt });
  });

  it('rejects invalid create options', () => {
    throws(() => createScryptRecord(PASSWORD, { ln: 0, r: 8, p: 1 }));
    throws(() => createScryptRecord(PASSWORD, { ln: 33, r: 8, p: 1 }));
    throws(() => createScryptRecord(PASSWORD, { ln: 1.5, r: 8, p: 1 }));
    throws(() => createScryptRecord(PASSWORD, { ln: 14, r: 0, p: 1 }));
    throws(() => createScryptRecord(PASSWORD, { ln: 14, r: 8, p: 0 }));
    throws(() => createScryptRecord(PASSWORD, { ln: 14, r: 8, p: 1, salt: Uint8Array.of() }));
    throws(() => createScryptRecord(PASSWORD, { ln: 14, r: 8, p: 1, dkLen: 0 }));
    throws(() => createScryptRecord(PASSWORD, { ln: 14, r: 8 }));
    throws(() => createScryptRecord(PASSWORD));
  });

  function validSaltHash() {
    const record = createScryptRecord(PASSWORD, { ...PARAMS, salt: SALT });
    return record.split('$').slice(3).join('$');
  }
});
