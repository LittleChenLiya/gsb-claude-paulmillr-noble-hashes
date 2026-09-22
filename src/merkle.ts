/**
 * Incremental Merkle tree over SHA-256.
 *
 * Rules (fixed):
 * - leaf:   H(0x00 || leafBytes)
 * - parent: H(0x01 || left || right)
 * - empty tree root: H(empty)
 * - odd node on a level is promoted as-is, never duplicated
 *
 * Costs (n = number of leaves):
 * - append: O(log n) hashes, O(1) amortized; root: O(log n) hashes from a frontier
 * - proof:  O(n) hashes (rebuilds levels from stored leaf digests)
 * - memory: O(n) leaf digests (32 bytes each) + O(log n) frontier
 * - proof size: 32 * ceil(log2(n)) bytes of siblings, plus index & tree size
 * @module
 */
import { sha256 } from './sha2.ts';
import { abytes, anumber, concatBytes, copyBytes, isBytes } from './utils.ts';

/** Digest size of SHA-256 in bytes. */
const DIGEST_LEN = 32;
/** Max number of leaves: indices and sizes must stay safe integers. */
const MAX_LEAVES = Number.MAX_SAFE_INTEGER;

const LEAF_TAG = /* @__PURE__ */ Uint8Array.of(0x00);
const PARENT_TAG = /* @__PURE__ */ Uint8Array.of(0x01);
const EMPTY = /* @__PURE__ */ new Uint8Array(0);

/** Hash of a leaf: H(0x00 || bytes). */
function leafHash(data: Uint8Array): Uint8Array {
  return sha256(concatBytes(LEAF_TAG, data));
}

/** Hash of an internal node: H(0x01 || left || right). */
function parentHash(left: Uint8Array, right: Uint8Array): Uint8Array {
  return sha256(concatBytes(PARENT_TAG, left, right));
}

function eqBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Inclusion proof for a single leaf.
 * Sibling positions (left/right) and missing (promoted) levels are derived
 * from leafIndex and treeSize, so they are not stored explicitly.
 */
export type MerkleProof = {
  /** 0-based index of the proven leaf. */
  leafIndex: number;
  /** Number of leaves in the tree the proof was made for. */
  treeSize: number;
  /** Sibling digests, bottom level first; exactly one per non-promoted level. */
  siblings: Uint8Array[];
};

/**
 * Number of siblings a valid proof for (leafIndex, treeSize) must contain.
 * A level contributes no sibling when the node is the odd last one (promoted).
 */
function expectedSiblings(leafIndex: number, treeSize: number): number {
  let count = 0;
  let idx = leafIndex;
  let width = treeSize;
  while (width > 1) {
    const promoted = width % 2 === 1 && idx === width - 1;
    if (!promoted) count++;
    idx = Math.floor(idx / 2);
    width = Math.ceil(width / 2);
  }
  return count;
}

/**
 * Append-only SHA-256 Merkle tree.
 * Leaf bytes are hashed immediately inside append(): mutating the caller's
 * buffer afterwards cannot change the tree.
 */
export class MerkleTree {
  private _size = 0;
  // Leaf digests, kept so proofs can be generated for any index.
  private readonly leaves: Uint8Array[] = [];
  // frontier[level] = root of the largest complete subtree ending at the last leaf.
  private readonly frontier: (Uint8Array | undefined)[] = [];

  /** Number of leaves appended so far. */
  get size(): number {
    return this._size;
  }

  /**
   * Adds a leaf. The leaf is hashed synchronously, so later mutations of the
   * passed buffer do not affect the tree. Throws if the tree would exceed
   * Number.MAX_SAFE_INTEGER leaves.
   */
  append(leaf: Uint8Array): void {
    abytes(leaf);
    if (this._size >= MAX_LEAVES) throw new Error('merkle: too many leaves');
    let hash = leafHash(leaf);
    this.leaves.push(hash);
    // Merge while the previous leaf count has a trailing 1-bit at this level.
    let level = 0;
    let n = this._size;
    while (n & 1) {
      hash = parentHash(this.frontier[level] as Uint8Array, hash);
      this.frontier[level] = undefined;
      level++;
      n >>>= 1;
    }
    this.frontier[level] = hash;
    this._size++;
  }

  /**
   * Root of the tree, computed incrementally from the frontier in O(log n).
   * Empty tree root is H(empty). Returns a fresh copy.
   */
  root(): Uint8Array {
    if (this._size === 0) return sha256(EMPTY);
    // Fold bottom-up: each higher frontier subtree sits to the left of the
    // accumulated smaller ones.
    let acc: Uint8Array | undefined;
    for (const node of this.frontier) {
      if (node === undefined) continue;
      acc = acc === undefined ? node : parentHash(node, acc);
    }
    return copyBytes(acc as Uint8Array);
  }

  /**
   * Inclusion proof for the leaf at leafIndex. Runs in O(n) hashes by
   * rebuilding levels from stored leaf digests. Throws on invalid index.
   */
  proof(leafIndex: number): MerkleProof {
    anumber(leafIndex, 'leafIndex');
    if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= this._size)
      throw new Error('merkle: invalid leaf index');
    const siblings: Uint8Array[] = [];
    let level: Uint8Array[] = this.leaves.slice();
    let idx = leafIndex;
    while (level.length > 1) {
      const promoted = level.length % 2 === 1 && idx === level.length - 1;
      if (!promoted) {
        const sib = idx % 2 === 0 ? idx + 1 : idx - 1;
        siblings.push(copyBytes(level[sib]));
      }
      const next: Uint8Array[] = [];
      for (let i = 0; i + 1 < level.length; i += 2) next.push(parentHash(level[i], level[i + 1]));
      if (level.length % 2 === 1) next.push(level[level.length - 1]);
      level = next;
      idx = Math.floor(idx / 2);
    }
    return { leafIndex, treeSize: this._size, siblings };
  }
}

/**
 * Verifies an inclusion proof against a root. Returns false (never throws on
 * malformed proofs) when:
 * - treeSize / leafIndex are not safe integers or out of range
 * - sibling count differs from what (leafIndex, treeSize) implies
 * - any sibling is not a 32-byte Uint8Array
 * - the folded root does not match
 */
export function verifyProof(root: Uint8Array, leaf: Uint8Array, proof: MerkleProof): boolean {
  if (!isBytes(root) || root.length !== DIGEST_LEN) return false;
  if (!isBytes(leaf)) return false;
  if (proof === null || typeof proof !== 'object') return false;
  const { leafIndex, treeSize, siblings } = proof;
  if (!Number.isSafeInteger(treeSize) || treeSize < 1) return false;
  if (!Number.isSafeInteger(leafIndex) || leafIndex < 0 || leafIndex >= treeSize) return false;
  if (!Array.isArray(siblings)) return false;
  if (siblings.length !== expectedSiblings(leafIndex, treeSize)) return false;
  for (const sib of siblings) if (!isBytes(sib) || sib.length !== DIGEST_LEN) return false;
  let hash = leafHash(leaf);
  let idx = leafIndex;
  let width = treeSize;
  let s = 0;
  while (width > 1) {
    const promoted = width % 2 === 1 && idx === width - 1;
    if (!promoted) {
      const sib = siblings[s++];
      hash = idx % 2 === 0 ? parentHash(hash, sib) : parentHash(sib, hash);
    }
    idx = Math.floor(idx / 2);
    width = Math.ceil(width / 2);
  }
  return eqBytes(hash, root);
}
