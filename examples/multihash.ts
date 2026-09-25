/**
 * Terminal demo for MultiHasher + hashStream.
 * Run: node examples/multihash.ts
 * Prints SHA-256/SHA-512 digests of "abc" (fed as a/bc chunks) and
 * cleanup counters proving cancellation destroys inner state exactly once.
 */
import { MultiHasher, hashStream } from '../src/multihash.ts';
import { sha256, sha512 } from '../src/sha2.ts';
import { bytesToHex, utf8ToBytes } from '../src/utils.ts';

const specs = () => [
  { name: 'sha256', create: () => sha256.create() },
  { name: 'sha512', create: () => sha512.create() },
];

// 1. Success path: "abc" fed as a/bc chunks through an async byte stream.
async function* abcChunks() {
  yield utf8ToBytes('a');
  yield utf8ToBytes('bc');
}
const digests = await hashStream(abcChunks(), new MultiHasher(specs()));
console.log('== multihash success ==');
for (const name of Object.keys(digests)) console.log(name + ':', bytesToHex(digests[name]));
console.log(
  'sha256 matches standalone:',
  bytesToHex(digests.sha256) === bytesToHex(sha256(utf8ToBytes('abc')))
);
console.log(
  'sha512 matches standalone:',
  bytesToHex(digests.sha512) === bytesToHex(sha512(utf8ToBytes('abc')))
);

// 2. Clone independence: same prefix, different suffixes.
const base = new MultiHasher(specs());
base.update(utf8ToBytes('a'));
const forked = base.clone();
base.update(utf8ToBytes('bc'));
forked.update(utf8ToBytes('XYZ'));
console.log('== clone independence ==');
console.log('base   sha256:', bytesToHex(base.digest().sha256));
console.log('forked sha256:', bytesToHex(forked.digest().sha256));

// 3. Cancellation cleanup: counting fake hashes + a stream that fails mid-read.
const counters = [];
function countingFake() {
  return {
    create() {
      const state = { destroyed: 0 };
      counters.push(state);
      const hash = {
        blockLen: 4,
        outputLen: 4,
        canXOF: false,
        update() {
          return hash;
        },
        digest() {
          return new Uint8Array(4);
        },
        digestInto() {},
        destroy() {
          state.destroyed++;
        },
        clone() {
          return countingFake().create();
        },
        _cloneInto() {
          return hash;
        },
      };
      return hash;
    },
  };
}
let returned = 0;
const failingStream = {
  [Symbol.asyncIterator]() {
    let index = 0;
    return {
      async next() {
        if (index++ === 1) throw new Error('simulated read failure');
        return { done: false, value: utf8ToBytes('chunk' + index) };
      },
      async return() {
        returned++;
        return { done: true, value: undefined };
      },
    };
  },
};
const mh = new MultiHasher([
  { name: 'fake-a', create: countingFake().create },
  { name: 'fake-b', create: countingFake().create },
]);
try {
  await hashStream(failingStream, mh);
} catch (err) {
  console.log('== cancel/error cleanup ==');
  console.log('caught:', err.message);
}
mh.destroy(); // idempotent: must not bump the counters
console.log('iterator closed (return calls):', returned);
console.log('destroy counts:', counters.map((c) => c.destroyed).join(', '), '(expected 1, 1)');
