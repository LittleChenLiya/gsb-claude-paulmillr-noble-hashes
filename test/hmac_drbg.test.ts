import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import {
  HMAC_DRBG,
  HMAC_DRBG_MAX_GENERATE_BYTES,
  HMAC_DRBG_MIN_ENTROPY_BYTES,
  HMAC_DRBG_MIN_NONCE_BYTES,
  HMAC_DRBG_RESEED_INTERVAL,
} from '../src/hmac_drbg.ts';
import { bytesToHex, hexToBytes } from '../src/utils.ts';

// NIST SP 800-90A Rev. 1 HMAC_DRBG (SHA-256) known-answer vectors, NIST CAVS 14.3
// (CAVP DRBGVS, "HMAC_DRBG" test vectors; original public source:
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/drbg/drbgtestvectors.zip).
// Hex fixtures below are transcribed unmodified from the public Mbed TLS mirror:
// https://github.com/Mbed-TLS/mbedtls/blob/mbedtls-3.6/tests/suites/test_suite_hmac_drbg.no_reseed.data
// https://github.com/Mbed-TLS/mbedtls/blob/mbedtls-3.6/tests/suites/test_suite_hmac_drbg.nopr.data
// They are fixed local fixtures, not outputs of this implementation.
// Each case: instantiate(entropy, nonce, perso), optional reseed, then two
// generate(128, additionalInput) calls; 'expected' is the SECOND generate result.
const VECTORS = [
  {
    name: 'CAVS 14.3 No Reseed (SHA-256,256+128,0,0) #0',
    entropy: 'ca851911349384bffe89de1cbdc46e6831e44d34a4fb935ee285dd14b71a7488',
    nonce: '659ba96c601dc69fc902940805ec0ca8',
    perso: '',
    expected:
      'e528e9abf2dece54d47c7e75e5fe302149f817ea9fb4bee6f4199697d04d5b89' +
      'd54fbb978a15b5c443c9ec21036d2460b6f73ebad0dc2aba6e624abf07745bc107' +
      '694bb7547bb0995f70de25d6b29e2d3011bb19d27676c07162c8b5ccde0668961d' +
      'f86803482cb37ed6d5c0bb8d50cf1f50d476aa0458bdaba806f48be9dcb8',
  },
  {
    name: 'CAVS 14.3 No Reseed (SHA-256,256+128,0,256) #0 (additionalInput on generate)',
    entropy: 'd3cc4d1acf3dde0c4bd2290d262337042dc632948223d3a2eaab87da44295fbd',
    nonce: '0109b0e729f457328aa18569a9224921',
    perso: '',
    add1: '3c311848183c9a212a26f27f8c6647e40375e466a0857cc39c4e47575d53f1f6',
    add2: 'fcb9abd19ccfbccef88c9c39bfb3dd7b1c12266c9808992e305bc3cff566e4e4',
    expected:
      '9c7b758b212cd0fcecd5daa489821712e3cdea4467b560ef5ddc24ab47749a1f' +
      '1ffdbbb118f4e62fcfca3371b8fbfc5b0646b83e06bfbbab5fac30ea09ea2bc76f' +
      '1ea568c9be0444b2cc90517b20ca825f2d0eccd88e7175538b85d90ab390183ca6' +
      '395535d34473af6b5a5b88f5a59ee7561573337ea819da0dcc3573a22974',
  },
  {
    name: 'CAVS 14.3 PR False (SHA-256, 256, 256) #0 (explicit reseed)',
    entropy: 'cdb0d9117cc6dbc9ef9dcb06a97579841d72dc18b2d46a1cb61e314012bdf416',
    nonce: 'd0c0d01d156016d0eb6b7e9c7c3c8da8',
    perso: '6f0fb9eab3f9ea7ab0a719bfa879bf0aaed683307fda0c6d73ce018b6e34faaa',
    reseedEntropy: '8ec6f7d5a8e2e88f43986f70b86e050d07c84b931bcf18e601c5a3eee3064c82',
    reseedAdd: '1ab4ca9014fa98a55938316de8ba5a68c629b0741bdd058c4d70c91cda5099b3',
    add1: '16e2d0721b58d839a122852abd3bf2c942a31c84d82fca74211871880d7162ff',
    add2: '53686f042a7b087d5d2eca0d2a96de131f275ed7151189f7ca52deaa78b79fb2',
    expected:
      'dda04a2ca7b8147af1548f5d086591ca4fd951a345ce52b3cd49d47e84aa31a1' +
      '83e31fbc42a1ff1d95afec7143c8008c97bc2a9c091df0a763848391f68cb4a366' +
      'ad89857ac725a53b303ddea767be8dc5f605b1b95f6d24c9f06be65a973a089320' +
      'b3cc42569dcfd4b92b62a993785b0301b3fc452445656fce22664827b88f',
  },
  {
    name: 'CAVS 14.3 PR False (SHA-256, 0, 0) #0 (explicit reseed, no additional input)',
    entropy: '06032cd5eed33f39265f49ecb142c511da9aff2af71203bffaf34a9ca5bd9c0d',
    nonce: '0e66f71edc43e42a45ad3c6fc6cdc4df',
    perso: '',
    reseedEntropy: '01920a4e669ed3a85ae8a33b35a74ad7fb2a6bb4cf395ce00334a9c9a5a5d552',
    expected:
      '76fc79fe9b50beccc991a11b5635783a83536add03c157fb30645e611c2898bb' +
      '2b1bc215000209208cd506cb28da2a51bdb03826aaf2bd2335d576d519160842e7' +
      '158ad0949d1a9ec3e66ea1b1a064b005de914eac2e9d4f2d72a8616a8022542291' +
      '8250ff66a41bd2f864a6a38cc5b6499dc43f7f2bd09e1e0f8f5885935124',
  },
];

const h = (hex: string) => (hex === '' ? new Uint8Array(0) : hexToBytes(hex));

function runVector(v: (typeof VECTORS)[number]): Uint8Array {
  const drbg = HMAC_DRBG.instantiate(h(v.entropy), h(v.nonce), h(v.perso));
  if (v.reseedEntropy !== undefined) drbg.reseed(h(v.reseedEntropy), h(v.reseedAdd ?? ''));
  drbg.generate(128, h(v.add1 ?? ''));
  return drbg.generate(128, h(v.add2 ?? ''));
}

describe('hmac_drbg', () => {
  it('matches NIST CAVS 14.3 HMAC_DRBG SHA-256 vectors', () => {
    for (const v of VECTORS) eql(bytesToHex(runVector(v)), v.expected, v.name);
  });

  it('validates instantiate inputs', () => {
    const okE = new Uint8Array(HMAC_DRBG_MIN_ENTROPY_BYTES);
    const okN = new Uint8Array(HMAC_DRBG_MIN_NONCE_BYTES);
    throws(() => HMAC_DRBG.instantiate(new Uint8Array(31), okN), RangeError);
    throws(() => HMAC_DRBG.instantiate(okE, new Uint8Array(15)), RangeError);
    // @ts-expect-error: not a Uint8Array
    throws(() => HMAC_DRBG.instantiate('x'.repeat(32), okN), TypeError);
    // @ts-expect-error: not a Uint8Array
    throws(() => HMAC_DRBG.instantiate(okE, okN, 5), TypeError);
    HMAC_DRBG.instantiate(okE, okN).destroy();
  });

  it('rejects invalid generate lengths without changing state', () => {
    const seed = hexToBytes('aa'.repeat(32));
    const nonce = hexToBytes('bb'.repeat(16));
    const a = HMAC_DRBG.instantiate(seed, nonce);
    const b = HMAC_DRBG.instantiate(seed, nonce);
    // Invalid calls on instance A first: must throw and leave state untouched.
    for (const bad of [0, -1, 1.5, Number.NaN, HMAC_DRBG_MAX_GENERATE_BYTES + 1])
      throws(() => a.generate(bad), RangeError, `nbytes=${bad}`);
    // @ts-expect-error: not a number
    throws(() => a.generate('32'), TypeError);
    // A (after rejected calls) and B (direct) must produce identical output.
    eql(a.generate(48), b.generate(48));
    eql(a.generate(64), b.generate(64));
  });

  it('rejects invalid reseed without changing state', () => {
    const seed = hexToBytes('cc'.repeat(32));
    const nonce = hexToBytes('dd'.repeat(16));
    const a = HMAC_DRBG.instantiate(seed, nonce);
    const b = HMAC_DRBG.instantiate(seed, nonce);
    a.generate(32);
    b.generate(32);
    throws(() => a.reseed(new Uint8Array(10)), RangeError);
    // @ts-expect-error: not a Uint8Array
    throws(() => a.reseed(new Uint8Array(32), 'x'), TypeError);
    eql(a.generate(32), b.generate(32));
  });

  it('isolates caller buffers: mutating seeds or outputs has no effect', () => {
    const entropy = hexToBytes('01'.repeat(32));
    const nonce = hexToBytes('02'.repeat(16));
    const perso = hexToBytes('03'.repeat(8));
    const a = HMAC_DRBG.instantiate(entropy, nonce, perso);
    const b = HMAC_DRBG.instantiate(
      hexToBytes('01'.repeat(32)),
      hexToBytes('02'.repeat(16)),
      hexToBytes('03'.repeat(8))
    );
    // Caller corrupts its own copies after instantiate.
    entropy.fill(0xff);
    nonce.fill(0xff);
    perso.fill(0xff);
    const outA = a.generate(64);
    const outB = b.generate(64);
    eql(outA, outB);
    // Caller corrupts the returned buffer; subsequent output is unaffected.
    outA.fill(0x00);
    eql(a.generate(64), b.generate(64));
    // Returned array must not alias internal state: distinct arrays per call.
    const c = HMAC_DRBG.instantiate(hexToBytes('01'.repeat(32)), hexToBytes('02'.repeat(16)));
    const o1 = c.generate(32);
    const o2 = c.generate(32);
    eql(o1 === o2, false);
  });

  it('enforces the 2^48 reseed interval exactly', () => {
    eql(HMAC_DRBG_RESEED_INTERVAL, 281474976710656n);
    const seed = hexToBytes('0a'.repeat(32));
    const nonce = hexToBytes('0b'.repeat(16));
    const a = HMAC_DRBG.instantiate(seed, nonce);
    const b = HMAC_DRBG.instantiate(seed, nonce);
    a.generate(32);
    b.generate(32);
    eql(a.reseedCounter, 2n);
    // At the boundary the request still succeeds.
    (a as any).counter = HMAC_DRBG_RESEED_INTERVAL;
    a.generate(32);
    b.generate(32);
    // Past the boundary every request fails until reseed; state is unchanged.
    (a as any).counter = HMAC_DRBG_RESEED_INTERVAL + 1n;
    throws(() => a.generate(32), /reseed/);
    throws(() => a.generate(32), /reseed/);
    const fresh = hexToBytes('0c'.repeat(32));
    a.reseed(fresh);
    b.reseed(fresh);
    eql(a.reseedCounter, 1n);
    eql(a.generate(32), b.generate(32));
  });

  it('supports the maximum request size of 65536 bytes', () => {
    const drbg = HMAC_DRBG.instantiate(new Uint8Array(32), new Uint8Array(16));
    const out = drbg.generate(HMAC_DRBG_MAX_GENERATE_BYTES);
    eql(out.length, HMAC_DRBG_MAX_GENERATE_BYTES);
    drbg.destroy();
  });

  it('destroy zeroizes state and makes all operations fail', () => {
    const drbg = HMAC_DRBG.instantiate(new Uint8Array(32).fill(7), new Uint8Array(16).fill(8));
    drbg.generate(32);
    drbg.destroy();
    eql(drbg.reseedCounter, 0n);
    // Internal buffers are wiped.
    eql(Array.from((drbg as any).K), new Array(32).fill(0));
    eql(Array.from((drbg as any).V), new Array(32).fill(0));
    // No operation can resurrect a usable state.
    throws(() => drbg.generate(1), /destroyed/);
    throws(() => drbg.reseed(new Uint8Array(32)), /destroyed/);
    throws(() => drbg.generate(32), /destroyed/);
  });
});

it.runWhen(import.meta.url);
