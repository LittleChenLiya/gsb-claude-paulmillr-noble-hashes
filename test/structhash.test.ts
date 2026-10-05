import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, notDeepStrictEqual as notEql, throws } from 'node:assert';
import { sha256 } from '../src/sha2.ts';
import {
  StructHasher,
  TAG_BYTES,
  TAG_STRING,
  TAG_UINT,
  createStructHasher,
  encodeStructField,
  encodeStructValue,
  structHash,
} from '../src/structhash.ts';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../src/utils.ts';

const hex = bytesToHex;

describe('structhash byte protocol', () => {
  it('encodes values as tag || u32be(len) || content', () => {
    eql(hex(encodeStructValue('')), '0200000000');
    eql(hex(encodeStructValue('ab')), '02000000026162');
    eql(hex(encodeStructValue(hexToBytes('deadbeef'))), '0100000004deadbeef');
    eql(hex(encodeStructValue(1)), '03000000080000000000000001');
    eql(hex(encodeStructValue(0xffffffffffffffffn)), '0300000008ffffffffffffffff');
    eql(encodeStructValue(new Uint8Array(0))[0], TAG_BYTES);
    eql(encodeStructValue('')[0], TAG_STRING);
    eql(encodeStructValue(0)[0], TAG_UINT);
  });
  it('encodes fields as tagged name || tagged value', () => {
    eql(hex(encodeStructField('a', 1)), '02000000016103000000080000000000000001');
    eql(hex(encodeStructField('msg', 'ab')), '02000000036d736702000000026162');
    eql(hex(encodeStructField('d', hexToBytes('deadbeef'))), '0200000001640100000004deadbeef');
  });
  it('rejects u32 length overflow instead of wrapping', () => {
    // Cannot allocate 4 GiB in a test: spoof the declared length of a real Uint8Array.
    const huge = new Proxy(new Uint8Array(0), {
      get(t, p) {
        if (p === 'length') return 0x100000000;
        return Reflect.get(t, p);
      },
    });
    throws(() => encodeStructValue(huge), /overflows fixed-width u32/);
    throws(() => structHash([['a', huge]]), /overflows fixed-width u32/);
  });
  it('rejects u64 / u32 integer overflow', () => {
    throws(() => encodeStructValue(1n << 64n), /overflows fixed-width u64/);
    throws(() => encodeStructValue(-1n), /overflows fixed-width u64/);
    throws(() => encodeStructValue(-1));
    throws(() => encodeStructValue(1.5));
    throws(() => encodeStructValue(2 ** 53));
    throws(() => createStructHasher({ version: 0x100000000 }), /overflows fixed-width u32/);
    throws(() => createStructHasher({ version: -1 }));
    // Boundary values are accepted.
    eql(hex(encodeStructValue(0xffffffffffffffffn)).slice(10), 'ffffffffffffffff');
    createStructHasher({ version: 0xffffffff }).destroy();
  });
});

describe('structhash vectors', () => {
  const VECTORS: [
    string,
    Parameters<typeof structHash>[0],
    Parameters<typeof structHash>[1],
    string,
  ][] = [
    ['empty', [], undefined, '474fa71f888c9b3d2e55bb5cfa789c9284fc793a1d5c557aa78a9e962702867e'],
    [
      'string 1',
      [['a', '1']],
      undefined,
      '552a29e65f37023105deb0b2b8807347934440f4a8129edc7ca19a8c24ebbffb',
    ],
    [
      'uint 1',
      [['a', 1]],
      undefined,
      '703b07b5f63e1ea3cbd6a75a0af87365ab1249531845db2f899d02103204513b',
    ],
    [
      'hello',
      [['msg', 'hello']],
      undefined,
      '426e8368a648dc58ba44d9cc613f7966e19c23b0d804584359fd043e1c88e393',
    ],
    [
      'uint field',
      [['n', 1]],
      undefined,
      'a812adcf2a59eaac0cc87c248762fcba9888487c9e14fd76a0efc61ed46620da',
    ],
    [
      'bytes',
      [['data', hexToBytes('deadbeef')]],
      undefined,
      'dfe5048a0c3847435dfe7ac97c30abfed8d9d3b005ab4ed3e1c765f8bacdff36',
    ],
    [
      'ab+c',
      [
        ['x', 'ab'],
        ['y', 'c'],
      ],
      undefined,
      'a3c6292eb21f38dd96a8f7d37d8787e90144a76667c306bfcf966a555b3b1047',
    ],
    [
      'a+bc',
      [
        ['x', 'a'],
        ['y', 'bc'],
      ],
      undefined,
      '6ff2fc48c2af8597afcc280a8428c4bc5a7c955fce83294b608163dd157bdbe5',
    ],
    [
      'empty v2',
      [],
      { version: 2 },
      '324d7a223caa286b203c42146a7c9c7f1b0df04515c8c8ffa88335bfffaab0ae',
    ],
    [
      'mixed',
      [
        ['user', 'alice'],
        ['uid', 1],
        ['raw', hexToBytes('00ff')],
      ],
      undefined,
      '4dc751108641e63d1925349a0465885485b0991ce211162961558ddd66b41524',
    ],
  ];
  for (const [name, fields, opts, expected] of VECTORS) {
    it(name, () => {
      eql(hex(structHash(fields, opts)), expected);
      // Incremental hashing matches the one-shot interface.
      const h = createStructHasher(opts);
      for (const [n, v] of fields) h.update(n, v);
      eql(hex(h.digest()), expected);
    });
  }
});

describe('structhash unambiguity', () => {
  it('field boundaries matter: ab+c != a+bc', () => {
    notEql(
      structHash([
        ['x', 'ab'],
        ['y', 'c'],
      ]),
      structHash([
        ['x', 'a'],
        ['y', 'bc'],
      ])
    );
    // Splitting one field into two is not a no-op either.
    notEql(
      structHash([['x', 'ab']]),
      structHash([
        ['x', 'a'],
        ['y', 'b'],
      ])
    );
  });
  it('types matter: string "1" != uint 1 != bytes 0x31', () => {
    const asStr = structHash([['a', '1']]);
    const asInt = structHash([['a', 1]]);
    const asBytes = structHash([['a', utf8ToBytes('1')]]);
    notEql(asStr, asInt);
    notEql(asStr, asBytes);
    notEql(asInt, asBytes);
    // number and bigint forms of the same uint encode identically.
    eql(structHash([['a', 1]]), structHash([['a', 1n]]));
  });
  it('field order matters', () => {
    notEql(
      structHash([
        ['a', '1'],
        ['b', '2'],
      ]),
      structHash([
        ['b', '2'],
        ['a', '1'],
      ])
    );
  });
  it('protocol version enters the digest', () => {
    eql(structHash([]), structHash([], { version: 1 }));
    notEql(structHash([], { version: 1 }), structHash([], { version: 2 }));
    notEql(structHash([['a', 1]], { version: 1 }), structHash([['a', 1]], { version: 0xffffffff }));
  });
  it('rejects duplicate field names', () => {
    throws(
      () =>
        structHash([
          ['a', 'x'],
          ['a', 'y'],
        ]),
      /duplicate field name/
    );
    const h = createStructHasher();
    h.update('a', 'x');
    throws(() => h.update('a', 'y'), /duplicate field name/);
    h.destroy();
  });
});

describe('structhash incremental state', () => {
  it('failed encoding does not update state', () => {
    const h = createStructHasher();
    h.update('a', 'x');
    const bad: [unknown, unknown][] = [
      ['a', 'y'], // duplicate name
      [1, 'y'], // non-string name
      ['b', true], // unsupported type
      ['b', null], // unsupported type
      ['b', {}], // unsupported type
      ['b', undefined], // unsupported type
      ['b', -1], // negative int
      ['b', 1.5], // non-integer
      ['b', 2 ** 53], // unsafe integer
      ['b', 1n << 64n], // u64 overflow
      ['b', -1n], // negative bigint
    ];
    for (const [name, value] of bad) throws(() => h.update(name as any, value as any));
    // State is exactly as if only the valid field had been absorbed.
    eql(h.digest(), structHash([['a', 'x']]));
  });
  it('clone, digestInto and finalization', () => {
    const h = new StructHasher();
    h.update('a', '1');
    const c = h.clone();
    throws(() => c.update('a', '2'), /duplicate field name/); // seen-set is cloned too
    h.update('b', 2);
    c.update('b', 2);
    eql(c.digest(), h.digest());
    const h2 = createStructHasher({ version: 7 });
    h2.update('n', 1);
    const out = new Uint8Array(32);
    h2.digestInto(out);
    eql(out, structHash([['n', 1]], { version: 7 }));
    throws(() => h2.update('x', 1), /after digest/);
  });
});

describe('structhash leaves plain hashes untouched', () => {
  it('sha256 still matches its standard vector', () => {
    eql(
      hex(sha256(utf8ToBytes('abc'))),
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
    eql(hex(sha256.create().update(utf8ToBytes('abc')).digest()), hex(sha256(utf8ToBytes('abc'))));
  });
});

it.runWhen(import.meta.url);
