import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, equal, ok, throws } from 'node:assert';
import { sha256 } from '../src/sha2.ts';
import {
  EMPTY_MERKLE_ROOT,
  MerkleTree,
  verifyMerkleProof,
  type MerkleProof,
} from '../src/merkle.ts';

// Independent naive reference: full rebuild from raw leaves every time.
const hLeaf = (d: Uint8Array) => sha256(new Uint8Array([0, ...d]));
const hParent = (l: Uint8Array, r: Uint8Array) => sha256(new Uint8Array([1, ...l, ...r]));

function naiveRoot(leaves: Uint8Array[]): Uint8Array {
  if (leaves.length === 0) return sha256(new Uint8Array(0));
  let level = leaves.map(hLeaf);
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2)
      next.push(i + 1 < level.length ? hParent(level[i], level[i + 1]) : level[i]);
    level = next;
  }
  return level[0];
}

// Naive proof, derived independently (no frontier bookkeeping).
function naiveProof(leaves: Uint8Array[], index: number): MerkleProof {
  let level = leaves.map(hLeaf);
  const siblings: Uint8Array[] = [];
  const path: number[] = [];
  let width = 1;
  const n = leaves.length;
  while (width < n) {
    const p = Math.floor(index / width);
    if (p % 2 === 1) {
      path.push(width);
      siblings.push(level[p - 1]);
    } else if ((p + 1) * width < n) {
      path.push(Math.min(width, n - (p + 1) * width));
      siblings.push(level[p + 1]);
    } else {
      path.push(0);
    }
    width *= 2;
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2)
      next.push(i + 1 < level.length ? hParent(level[i], level[i + 1]) : level[i]);
    level = next;
  }
  return { size: leaves.length, index, path, siblings };
}

const leaf = (i: number) => new TextEncoder().encode(`leaf-${i}`);

describe('merkle', () => {
  it('empty tree root is H(empty)', () => {
    eql(new MerkleTree().root, sha256(new Uint8Array(0)));
    eql(new MerkleTree().root, EMPTY_MERKLE_ROOT);
  });

  it('roots match naive rebuild for n = 1, 2, 3, 5 (and 4, 7)', () => {
    for (const n of [1, 2, 3, 4, 5, 7]) {
      const data = Array.from({ length: n }, (_, i) => leaf(i));
      const t = new MerkleTree();
      data.forEach((d) => t.append(d));
      equal(t.size, n);
      eql(t.root, naiveRoot(data), `n=${n}`);
    }
  });

  it('every leaf proof verifies for n = 0(empty), 1, 2, 3, 5', () => {
    for (const n of [1, 2, 3, 5]) {
      const data = Array.from({ length: n }, (_, i) => leaf(i));
      const t = new MerkleTree();
      data.forEach((d) => t.append(d));
      for (let i = 0; i < n; i++) {
        const p = t.proof(i);
        eql(p, naiveProof(data, i), `proof structure n=${n} i=${i}`);
        ok(verifyMerkleProof(t.root, data[i], p), `verify n=${n} i=${i}`);
      }
    }
  });

  it('demo shape (3 leaves): valid proof succeeds', () => {
    const t = new MerkleTree().append(leaf(0)).append(leaf(1)).append(leaf(2));
    const p = t.proof(0);
    ok(verifyMerkleProof(t.root, leaf(0), p));
    // Leaf 2 is promoted at level 0: only one sibling digest expected.
    equal(t.proof(2).siblings.length, 1);
  });

  it('tamper cases for the 3-leaf tree all fail', () => {
    const t = new MerkleTree().append(leaf(0)).append(leaf(1)).append(leaf(2));
    const root = t.root;
    const p = t.proof(0);
    ok(verifyMerkleProof(root, leaf(0), p));
    // wrong index
    ok(!verifyMerkleProof(root, leaf(0), { ...p, index: 1 }));
    // wrong size
    ok(!verifyMerkleProof(root, leaf(0), { ...p, size: 4 }));
    ok(!verifyMerkleProof(root, leaf(0), { ...p, size: 2 }));
    // wrong leaf content
    ok(!verifyMerkleProof(root, leaf(1), p));
    // extra sibling: structural rejection, not just fold mismatch
    ok(!verifyMerkleProof(root, leaf(0), { ...p, siblings: [...p.siblings, new Uint8Array(32)] }));
    // missing sibling
    ok(!verifyMerkleProof(root, leaf(0), { ...p, siblings: [] }));
    // sibling with wrong length
    const badLen = new Uint8Array(31);
    ok(!verifyMerkleProof(root, leaf(0), { ...p, siblings: [badLen] }));
  });

  it('append hashes immediately; mutating input afterwards is harmless', () => {
    const buf = new Uint8Array([1, 2, 3]);
    const t = new MerkleTree();
    t.append(buf);
    const rootBefore = t.root;
    buf[0] = 99;
    t.append(buf);
    eql(t.root, naiveRoot([new Uint8Array([1, 2, 3]), new Uint8Array([99, 2, 3])]));
    eql(rootBefore, naiveRoot([new Uint8Array([1, 2, 3])]));
  });

  it('batched vs leaf-by-leaf appends yield identical roots/proofs', () => {
    const data = Array.from({ length: 5 }, (_, i) => leaf(i));
    const oneByOne = new MerkleTree();
    data.forEach((d) => oneByOne.append(d));
    const batched = new MerkleTree();
    for (const d of data) batched.append(d); // same op; also test mixed chunk sizes
    const sizes: number[] = [];
    const rolling = new MerkleTree();
    data.forEach((d, i) => {
      rolling.append(d);
      sizes.push(rolling.size);
    });
    eql(sizes, [1, 2, 3, 4, 5]);
    eql(batched.root, oneByOne.root);
    eql(rolling.root, oneByOne.root);
    for (let i = 0; i < 5; i++) eql(rolling.proof(i), oneByOne.proof(i));
  });

  it('illegal indices and non-safe-integer sizes are rejected', () => {
    const t = new MerkleTree().append(leaf(0));
    throws(() => t.proof(-1));
    throws(() => t.proof(1));
    throws(() => t.proof(1.5));
    throws(() => t.proof(Number.MAX_SAFE_INTEGER + 1));
    const root = t.root;
    for (const bad of [0, -1, NaN, 1.5, Number.MAX_SAFE_INTEGER + 1])
      ok(!verifyMerkleProof(root, leaf(0), { size: bad as number, index: 0, siblings: [] }));
    ok(
      !verifyMerkleProof(root, leaf(0), {
        size: 1,
        index: Number.MAX_SAFE_INTEGER + 1,
        siblings: [],
      })
    );
  });

  it('getter returns defensive copies; malformed inputs return false', () => {
    const t = new MerkleTree().append(leaf(0));
    const r = t.root;
    const expected = t.root;
    r[0] ^= 0xff;
    eql(t.root, expected); // root unaffected by mutating the returned copy
    const p = t.proof(0);
    p.siblings[0] = new Uint8Array(32);
    ok(verifyMerkleProof(t.root, leaf(0), t.proof(0)));
    ok(!verifyMerkleProof(new Uint8Array(31), leaf(0), t.proof(0)));
    ok(!verifyMerkleProof(t.root, 'no' as unknown as Uint8Array, t.proof(0)));
    ok(!verifyMerkleProof(t.root, leaf(0), null as unknown as MerkleProof));
  });
});
