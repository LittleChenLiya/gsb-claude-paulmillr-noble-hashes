import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { MerkleTree, verifyProof, type MerkleProof } from '../src/merkle.ts';
import { sha256 } from '../src/sha2.ts';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '../src/utils.ts';

// Naive reference implementation: rebuilds the whole tree from raw leaves every time.
const naive = {
  leaf: (d: Uint8Array) => sha256(concatBytes(Uint8Array.of(0), d)),
  parent: (l: Uint8Array, r: Uint8Array) => sha256(concatBytes(Uint8Array.of(1), l, r)),
  levels(leaves: Uint8Array[]): Uint8Array[][] {
    let level = leaves.map((l) => this.leaf(l));
    const levels = [level];
    while (level.length > 1) {
      const next: Uint8Array[] = [];
      for (let i = 0; i + 1 < level.length; i += 2) next.push(this.parent(level[i], level[i + 1]));
      if (level.length % 2 === 1) next.push(level[level.length - 1]); // promote, no duplication
      level = next;
      levels.push(level);
    }
    return levels;
  },
  root(leaves: Uint8Array[]): Uint8Array {
    if (leaves.length === 0) return sha256(new Uint8Array(0));
    const levels = this.levels(leaves);
    return levels[levels.length - 1][0];
  },
  proof(leaves: Uint8Array[], leafIndex: number): MerkleProof {
    const siblings: Uint8Array[] = [];
    let idx = leafIndex;
    for (const level of this.levels(leaves)) {
      if (level.length === 1) break;
      const promoted = level.length % 2 === 1 && idx === level.length - 1;
      if (!promoted) siblings.push(level[idx % 2 === 0 ? idx + 1 : idx - 1]);
      idx = Math.floor(idx / 2);
    }
    return { leafIndex, treeSize: leaves.length, siblings };
  },
};

const LEAVES = [0, 1, 2, 3, 4].map((i) => utf8ToBytes('leaf-' + i));

// Generated once with the naive implementation above.
const VECTORS: { size: number; root: string }[] = [
  { size: 0, root: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
  { size: 1, root: '305df59f9590c3c9ac63d2b2743c388e3792449078cebf7fb3dbe6471643b2b7' },
  { size: 2, root: '60a53eed0de87a90c8e59427c59c46253c33a76a09502a51801300927b7e6bdc' },
  { size: 3, root: 'cf763a041c81ceef1578a6083f75c61bef2e0014f2a3e683a97fcfca5be7f19a' },
  { size: 5, root: '00d21829a5503145348abcf712513eacf2a274211ad83e970202bb5b6d80b286' },
];

function treeOf(n: number): MerkleTree {
  const t = new MerkleTree();
  for (let i = 0; i < n; i++) t.append(LEAVES[i]);
  return t;
}

describe('merkle', () => {
  it('roots match naive implementation and static vectors', () => {
    for (const { size, root } of VECTORS) {
      const t = treeOf(size);
      eql(t.size, size);
      eql(bytesToHex(t.root()), root);
      eql(t.root(), naive.root(LEAVES.slice(0, size)));
    }
  });
  it('every leaf proof verifies (sizes 1, 2, 3, 5)', () => {
    for (const size of [1, 2, 3, 5]) {
      const t = treeOf(size);
      const root = t.root();
      for (let i = 0; i < size; i++) {
        const proof = t.proof(i);
        eql(proof, naive.proof(LEAVES.slice(0, size), i));
        eql(verifyProof(root, LEAVES[i], proof), true, `size=${size} idx=${i}`);
      }
    }
  });
  it('demo: 3-leaf tree, valid proof then tampered proofs fail', () => {
    const t = treeOf(3);
    const root = t.root();
    const proof = t.proof(1);
    eql(verifyProof(root, LEAVES[1], proof), true);
    // wrong index
    eql(verifyProof(root, LEAVES[1], { ...proof, leafIndex: 2 }), false);
    // wrong size (inconsistent with the derived level structure)
    eql(verifyProof(root, LEAVES[1], { ...proof, treeSize: 2 }), false);
    eql(verifyProof(root, LEAVES[1], { ...proof, treeSize: 5 }), false);
    // wrong leaf content
    eql(verifyProof(root, utf8ToBytes('leaf-x'), proof), false);
    // extra sibling
    eql(
      verifyProof(root, LEAVES[1], { ...proof, siblings: [...proof.siblings, sha256(LEAVES[0])] }),
      false
    );
    // missing sibling
    eql(verifyProof(root, LEAVES[1], { ...proof, siblings: proof.siblings.slice(1) }), false);
    // sibling of wrong length
    eql(
      verifyProof(root, LEAVES[1], { ...proof, siblings: [new Uint8Array(16), proof.siblings[1]] }),
      false
    );
  });
  it('append hashes immediately: mutating input buffer does not change the tree', () => {
    const t = new MerkleTree();
    const buf = utf8ToBytes('mutable');
    t.append(buf);
    const before = t.root();
    buf.fill(0xff);
    eql(t.root(), before);
    eql(verifyProof(before, utf8ToBytes('mutable'), t.proof(0)), true);
    eql(verifyProof(before, buf, t.proof(0)), false);
  });
  it('batched and one-by-one appends give identical roots', () => {
    const one = new MerkleTree();
    for (const leaf of LEAVES) one.append(leaf);
    const batched = treeOf(5);
    eql(one.root(), batched.root());
    // also against naive for a non-vector size
    const t7 = new MerkleTree();
    const raw7 = [0, 1, 2, 3, 4, 5, 6].map((i) => utf8ToBytes('item-' + i));
    for (const leaf of raw7) t7.append(leaf);
    eql(t7.root(), naive.root(raw7));
    for (let i = 0; i < 7; i++) eql(verifyProof(t7.root(), raw7[i], t7.proof(i)), true);
  });
  it('rejects invalid proof indexes', () => {
    const t = treeOf(3);
    for (const bad of [-1, 3, 1.5, NaN, Infinity, Number.MAX_SAFE_INTEGER])
      throws(() => t.proof(bad));
    throws(() => new MerkleTree().proof(0));
  });
  it('rejects appends beyond safe integer range', () => {
    const t = treeOf(1);
    (t as any)._size = Number.MAX_SAFE_INTEGER;
    throws(() => t.append(LEAVES[0]), /too many leaves/);
  });
  it('verifyProof rejects malformed inputs', () => {
    const t = treeOf(3);
    const root = t.root();
    const proof = t.proof(0);
    eql(verifyProof(new Uint8Array(31), LEAVES[0], proof), false); // bad root length
    eql(verifyProof(root, LEAVES[0], { ...proof, treeSize: 0 }), false);
    eql(verifyProof(root, LEAVES[0], { ...proof, treeSize: 2 ** 60 }), false);
    eql(verifyProof(root, LEAVES[0], { ...proof, leafIndex: 3 }), false);
    eql(verifyProof(root, LEAVES[0], { ...proof, siblings: 'x' as any }), false);
    eql(verifyProof(root, LEAVES[0], null as any), false);
    // wrong root of correct length
    eql(verifyProof(hexToBytes(bytesToHex(root).replace(/^../, '00')), LEAVES[0], proof), false);
  });
});
