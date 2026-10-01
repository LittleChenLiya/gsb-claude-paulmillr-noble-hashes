import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, equal, throws } from 'node:assert';
import { scrypt } from '../src/scrypt.ts';
// prettier-ignore
import {
  createScryptRecord,
  parseScryptRecord,
  verifyScryptRecord,
  type ScryptFn,
} from '../src/scrypt-record.ts';
import { bytesToHex, hexToBytes } from '../src/utils.ts';

const PASSWORD = 'correct horse battery staple';
const SALT = hexToBytes('000102030405060708090a0b0c0d0e0f');
const PARAMS = { ln: 14, r: 8, p: 1 };

// Counting scrypt double: proves whether verification reached the KDF.
function countingScrypt(): { fn: ScryptFn; calls: () => number } {
  let count = 0;
  const fn: ScryptFn = (password, salt, opts) => {
    count++;
    return scrypt(password, salt, opts);
  };
  return { fn, calls: () => count };
}

describe('scrypt-record', () => {
  it.serial('create with fixed salt: format, verify, re-parse', () => {
    const record = createScryptRecord(PASSWORD, { ...PARAMS, salt: SALT });
    // Fixed field order, unpadded standard base64, no stray whitespace.
    eql(/^\$scrypt\$ln=14,r=8,p=1\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/.test(record), true);
    // No '=' padding inside the base64 salt/hash segments.
    eql(record.slice('$scrypt$ln=14,r=8,p=1$'.length).includes('='), false);
    // Hash matches a direct scrypt call with the same inputs.
    const expected = scrypt(PASSWORD, SALT, { N: 2 ** 14, r: 8, p: 1, dkLen: 32 });
    const parsed = parseScryptRecord(record);
    eql(parsed.params, PARAMS); // re-parsed params identical to the original
    eql(parsed.salt, SALT);
    eql(parsed.hash, expected);
    eql(verifyScryptRecord(record, PASSWORD), true);
    eql(verifyScryptRecord(record, 'wrong password'), false);
  });

  it.serial('random salt records verify and round-trip params', () => {
    for (const params of [
      { ln: 4, r: 8, p: 1 },
      { ln: 10, r: 1, p: 2 },
      { ln: 12, r: 4, p: 3 },
    ]) {
      const record = createScryptRecord('pw', params);
      eql(parseScryptRecord(record).params, params);
      eql(verifyScryptRecord(record, 'pw'), true);
      eql(verifyScryptRecord(record, 'PW'), false);
    }
  });

  it.serial('rejects malformed structure and whitespace', () => {
    const good = createScryptRecord(PASSWORD, { ...PARAMS, salt: SALT });
    const head = '$scrypt$ln=14,r=8,p=1';
    const tail = good.slice(head.length);
    const bad = [
      '',
      'scrypt$ln=14,r=8,p=1' + tail, // missing leading $
      '$scrypt$ln=14,r=8,p=1', // missing salt and hash
      good + '$extra',
      '$scrypt$ln=14,r=8,p=1,$x=1' + tail, // too many params
      '$scrypt$ln=14,r=8' + tail, // too few params
      head + ' ' + tail, // trailing whitespace
      '$scrypt$ln=14, r=8,p=1' + tail, // inner whitespace
      '$scrypt$ln= 14,r=8,p=1' + tail, // whitespace after =
      head + '\t' + tail, // tab
      head + '\n' + tail, // newline
      ' ' + good, // leading whitespace
      '$scrypt$ln:14,r=8,p=1' + tail, // wrong separator
      '$scrypt$ln=14;r=8;p=1' + tail, // wrong delimiter
      '$scrypt$r=8,ln=14,p=1' + tail, // wrong order
      '$scrypt$LN=14,r=8,p=1' + tail, // case sensitive
    ];
    for (const record of bad) {
      throws(() => parseScryptRecord(record), record);
      throws(() => verifyScryptRecord(record, PASSWORD), record);
    }
  });

  it.serial('rejects duplicate parameters', () => {
    const good = createScryptRecord(PASSWORD, { ...PARAMS, salt: SALT });
    const saltHash = good.slice('$scrypt$ln=14,r=8,p=1'.length);
    const bad = [
      '$scrypt$ln=14,ln=14,r=8,p=1' + saltHash,
      '$scrypt$ln=14,r=8,r=8,p=1' + saltHash,
      '$scrypt$ln=14,r=8,p=1,p=1' + saltHash,
      '$scrypt$ln=14,r=8,ln=1' + saltHash, // repeated name in wrong slot
    ];
    for (const record of bad) throws(() => parseScryptRecord(record), record);
  });

  it.serial('rejects non-canonical numbers: plus sign, zeros, overflow', () => {
    const good = createScryptRecord(PASSWORD, { ...PARAMS, salt: SALT });
    const saltHash = good.slice('$scrypt$ln=14,r=8,p=1'.length);
    const bad = [
      '$scrypt$ln=+14,r=8,p=1' + saltHash, // leading plus
      '$scrypt$ln=14,r=+8,p=1' + saltHash,
      '$scrypt$ln=14,r=8,p=+1' + saltHash,
      '$scrypt$ln=-14,r=8,p=1' + saltHash, // negative
      '$scrypt$ln=014,r=8,p=1' + saltHash, // leading zero
      '$scrypt$ln=14,r=08,p=1' + saltHash,
      '$scrypt$ln=1.4e1,r=8,p=1' + saltHash, // exponent
      '$scrypt$ln=0xE,r=8,p=1' + saltHash, // hex
      '$scrypt$ln=14.0,r=8,p=1' + saltHash, // fraction
      '$scrypt$ln=,r=8,p=1' + saltHash, // empty
      '$scrypt$ln=9007199254740993,r=8,p=1' + saltHash, // 2**53+1 unsafe
      '$scrypt$ln=14,r=9007199254740993,p=1' + saltHash,
      '$scrypt$ln=14,r=8,p=99999999999999999999' + saltHash, // huge digits
    ];
    for (const record of bad) throws(() => parseScryptRecord(record), record);
  });

  it.serial('rejects invalid base64 in salt and hash', () => {
    const good = createScryptRecord(PASSWORD, { ...PARAMS, salt: SALT });
    const head = '$scrypt$ln=14,r=8,p=1$';
    const saltB64 = good.slice(head.length, good.indexOf('$', head.length));
    const hashB64 = good.slice(good.lastIndexOf('$') + 1);
    const bad = [
      head + '!' + '$' + hashB64, // invalid char in salt
      head + saltB64 + '$' + hashB64.slice(0, -1) + '!', // invalid char in hash
      head + saltB64 + '=' + '$' + hashB64, // padding not allowed
      head + saltB64 + '$' + hashB64 + '==',
      head + saltB64.slice(0, 1) + '$' + hashB64, // length % 4 == 1
      head + saltB64 + '$' + hashB64.slice(0, 1),
      head + '$' + hashB64, // empty salt
      head + saltB64 + '$', // empty hash
      head + saltB64.slice(0, -1) + '-' + '$' + hashB64, // base64url char
      head + saltB64 + '$' + hashB64.slice(0, -1) + '_',
      head + saltB64 + ' $' + hashB64, // whitespace inside salt
    ];
    for (const record of bad) throws(() => parseScryptRecord(record), record);
  });

  it.serial('rejects out-of-range ln', () => {
    const good = createScryptRecord(PASSWORD, { ...PARAMS, salt: SALT });
    const tail = good.slice('$scrypt$ln=14'.length);
    for (const ln of [0, 33, 64, 100, 4294967296]) {
      throws(() => parseScryptRecord('$scrypt$ln=' + ln + tail), 'ln=' + ln);
    }
  });

  it.serial('enforces memory budget boundary', () => {
    // memUsed = 128*r*(2**ln + p + 1)
    // ln=4, r=8, p=1 -> 1024 * (16 + 1 + 1) = 18432 exactly.
    const exact = '$scrypt$ln=4,r=8,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw';
    eql(parseScryptRecord(exact, { maxmem: 18432 }).params, { ln: 4, r: 8, p: 1 });
    throws(() => parseScryptRecord(exact, { maxmem: 18431 })); // one byte under
    // Default budget is 1 GiB + 2 KiB: ln=20,r=8,p=1 fits exactly, ln=21 does not.
    const atDefault = '$scrypt$ln=20,r=8,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw';
    eql(parseScryptRecord(atDefault).params.ln, 20);
    throws(() =>
      parseScryptRecord('$scrypt$ln=21,r=8,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw')
    );
    // Huge r also blows the budget before reaching scrypt.
    throws(() =>
      parseScryptRecord(
        '$scrypt$ln=10,r=4294967296,p=1$AAECAwQFBgcICQoLDA0ODw$AAECAwQFBgcICQoLDA0ODw'
      )
    );
    // create() enforces the same budget.
    throws(() => createScryptRecord('pw', { ln: 21, r: 8, p: 1 }));
  });

  it.serial('does not mutate caller-visible arrays', () => {
    const salt = SALT.slice();
    const saltBefore = SALT.slice();
    const record = createScryptRecord(PASSWORD, { ...PARAMS, salt });
    eql(salt, saltBefore); // create() leaves the caller salt untouched
    const parsed = parseScryptRecord(record);
    const parsedSalt = parsed.salt.slice();
    const parsedHash = parsed.hash.slice();
    eql(verifyScryptRecord(record, PASSWORD), true);
    eql(parsed.salt, parsedSalt); // verify() leaves parsed arrays untouched
    eql(parsed.hash, parsedHash);
  });

  it.serial('invalid records never reach scrypt (counting double)', () => {
    const counter = countingScrypt();
    const good = createScryptRecord(PASSWORD, { ...PARAMS, salt: SALT });
    const invalid = [
      'not-a-record',
      '$scrypt$ln=14,ln=14,r=8,p=1$AAEC$AAEC', // duplicate
      '$scrypt$ln=+14,r=8,p=1$AAEC$AAEC', // leading plus
      '$scrypt$ln=14,r=8,p=1$!!!!$AAEC', // bad base64
      '$scrypt$ln=9007199254740993,r=8,p=1$AAEC$AAEC', // overflow
      '$scrypt$ln=64,r=8,p=1$AAEC$AAEC', // huge ln
      '$scrypt$ln=30,r=8,p=1$AAEC$AAEC', // over memory budget
    ];
    for (const record of invalid) {
      throws(() => verifyScryptRecord(record, PASSWORD, { scryptImpl: counter.fn }), record);
    }
    eql(counter.calls(), 0); // no scrypt computation happened
    eql(verifyScryptRecord(good, PASSWORD, { scryptImpl: counter.fn }), true);
    eql(counter.calls(), 1); // valid record reaches scrypt exactly once
    eql(verifyScryptRecord(good, 'nope', { scryptImpl: counter.fn }), false);
    eql(counter.calls(), 2);
  });

  it.serial('verify respects custom maxmem', () => {
    const record = createScryptRecord(PASSWORD, { ...PARAMS, salt: SALT });
    const counter = countingScrypt();
    // ln=14, r=8, p=1 -> memUsed = 1024 * 16386 = 16779264
    throws(() =>
      verifyScryptRecord(record, PASSWORD, { maxmem: 16779263, scryptImpl: counter.fn })
    );
    eql(counter.calls(), 0);
    eql(verifyScryptRecord(record, PASSWORD, { maxmem: 16779264, scryptImpl: counter.fn }), true);
    eql(counter.calls(), 1);
  });
});

it.runWhen(import.meta.url);
