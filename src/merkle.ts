/**
 * Incrementally appendable SHA-256 Merkle tree.
 *
 * Domain-separated nodes (RFC 6962 style):
 * - leaf:   `H(0x00 || data)`
 * - parent: `H(0x01 || left || right)`
 * - empty tree root: `H('')`
 *
 * Odd levels never duplicate the last node: it is promoted unchanged.
 * The root is maintained from a binary frontier, so `append()` costs
 * O(1) hashes amortized instead of rebuilding the whole tree.
 * @module
 */
import { abytes, copyBytes, type TRet } from './utils.ts';
import { sha256 } from './sha2.ts';

const DIGEST_LEN = 32;

/** Root of the empty tree: `H('')` (SHA-256 of the empty byte string). */
export const EMPTY_MERKLE_ROOT: TRet<Uint8Array> = /* @__PURE__ */ sha256(new Uint8Array(0));

const leafHash = (data: Uint8Array): Uint8Array => sha256(new Uint8Array([0, ...data]));
const parentHash = (left: Uint8Array, right: Uint8Array): Uint8Array =>
  sha256(new Uint8Array([1, ...left, ...right]));

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  let diff = 0;
  for (let i = 0; i < DIGEST_LEN; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function safeIndex(n: number, title: string): void {
  if (typeof n !== 'number' || !Number.isSafeInteger(n))
    throw new Error(`${title}: expected safe integer, got ${n}`);
}

/**
 * Inclusion proof for one leaf.
 *
 * `path` has one entry per tree level (leaf-to-root): the entry is the number
 * of leaves covered by the sibling at that level (`2^k` for a complete
 * subtree, smaller for a promoted trailing fragment), or `0` when the node is
 * promoted at that level (no sibling). `siblings` holds one 32-byte digest per
 * nonzero `path` entry, in the same order. The verifier recomputes the whole
 * `path` from `size` + `index` and compares it entry by entry, so tampering
 * with the size/index or adding, dropping, or shortening a sibling digest
 * rejects the proof even if some other fold reaches the claimed root.
 */
export type MerkleProof = {
  /** Tree size the proof was generated against. */
  size: number;
  /** Zero-based leaf index. */
  index: number;
  /** Per-level sibling leaf span; 0 marks a promoted (sibling-less) level. */
  path: number[];
  /** Sibling digests in leaf-to-root order (sparse: promoted levels omitted). */
  siblings: Uint8Array[];
};

/**
 * Append-only SHA-256 Merkle tree with a frontier-based root.
 *
 * Memory: O(n) digests (all leaf digests plus complete subtree roots,
 * ~2n entries total), which also enables O(log n) proof generation.
 */
export class MerkleTree {
  private sizeInternal = 0;
  // levels[k] holds roots of complete 2^k-sized subtrees in append order:
  // levels[0] is every leaf digest, levels[1] every paired node, etc.
  private levels: Uint8Array[][] = [];
  private cachedRoot: Uint8Array | undefined;

  /** Number of appended leaves. */
  get size(): number {
    return this.sizeInternal;
  }

  /**
   * Hash `data` immediately as `H(0x00 || data)` and append the digest.
   * Later mutation of `data` cannot affect the tree: the raw bytes are never
   * stored. Amortized O(1) hashes (binary carry), O(log n) worst case.
   */
  append(data: Uint8Array): this {
    abytes(data, undefined, 'data');
    if (this.sizeInternal >= Number.MAX_SAFE_INTEGER)
      throw new Error('tree is full: size exceeds MAX_SAFE_INTEGER');
    let node = leafHash(data);
    let level = this.levels[0];
    if (!level) this.levels.push((level = []));
    level.push(node);
    // Binary carry: pair with the completed subtree on the left while the
    // current frontier position is a right child (odd position).
    let pos = this.sizeInternal;
    let k = 0;
    while (pos % 2 === 1) {
      const left = this.levels[k][this.levels[k].length - 2];
      node = parentHash(left, node);
      pos = Math.floor(pos / 2);
      k += 1;
      if (!this.levels[k]) this.levels.push([]);
      this.levels[k].push(node);
    }
    this.sizeInternal += 1;
    this.cachedRoot = undefined;
    return this;
  }

  /**
   * Current root. Folds the O(log n) frontier (no full-tree rebuild):
   * O(log n) time, O(1) extra memory. Returns a defensive copy.
   */
  get root(): Uint8Array {
    if (this.sizeInternal === 0) return copyBytes(EMPTY_MERKLE_ROOT);
    if (!this.cachedRoot) {
      let acc: Uint8Array | null = null;
      for (const level of this.levels) {
        if (level.length % 2 === 1) {
          const last = level[level.length - 1];
          acc = acc === null ? last : parentHash(last, acc);
        }
      }
      this.cachedRoot = acc as Uint8Array;
    }
    return copyBytes(this.cachedRoot);
  }

  /**
   * Inclusion proof for leaf `index`. O(log n) time and O(log n) digests.
   * Every returned digest is a copy; callers may mutate it freely.
   */
  proof(index: number): MerkleProof {
    safeIndex(index, 'index');
    if (index < 0 || index >= this.sizeInternal)
      throw new Error(`index ${index} out of range (size=${this.sizeInternal})`);
    const siblings: Uint8Array[] = [];
    const path: number[] = [];
    let width = 1;
    let k = 0;
    while (width < this.sizeInternal) {
      const pos = Math.floor(index / width);
      if (pos % 2 === 1) {
        // Right child: left sibling is always a real node.
        path.push(width);
        siblings.push(copyBytes(this.levels[k][pos - 1]));
      } else {
        const rightStart = (pos + 1) * width;
        if (rightStart < this.sizeInternal) {
          // Right sibling exists. It is either a complete subtree stored in
          // levels[k], or a promoted trailing fragment rebuilt in O(log n).
          const level = this.levels[k];
          const span = Math.min(width, this.sizeInternal - rightStart);
          path.push(span);
          if (pos + 1 < level.length) siblings.push(copyBytes(level[pos + 1]));
          else siblings.push(this.fragmentRoot(k, rightStart));
        } else {
          // Promoted unchanged at this level: no sibling, structural marker.
          path.push(0);
        }
      }
      width *= 2;
      k += 1;
    }
    return { size: this.sizeInternal, index, path, siblings };
  }

  // Odd-promotion root of leaves [start, size), where start is a multiple of
  // 2^k and the fragment is smaller than 2^k. Folds stored level nodes in O(k).
  private fragmentRoot(k: number, start: number): Uint8Array {
    let acc: Uint8Array | null = null;
    let width = 1;
    for (let j = 0; j < k; j++) {
      const count = Math.floor((this.sizeInternal - start) / width);
      if (count % 2 === 1) {
        const node = this.levels[j][start / width + count - 1];
        acc = acc === null ? node : parentHash(node, acc);
      }
      width *= 2;
    }
    return copyBytes(acc as Uint8Array);
  }
}

/**
 * Independently verify an inclusion {@link MerkleProof} against `root`.
 *
 * The fold direction and sibling presence on every level are derived solely
 * from `proof.size` and `proof.index`: any extra sibling, missing sibling, or
 * sibling whose length is not 32 bytes rejects the proof, even if some other
 * fold could reach the claimed root. Never throws on malformed input; returns
 * `false` instead.
 *
 * O(log size) time, O(log size) memory. Browser-safe (no Node APIs).
 */
export function verifyMerkleProof(root: Uint8Array, leaf: Uint8Array, proof: MerkleProof): boolean {
  try {
    abytes(root, DIGEST_LEN, 'root');
    abytes(leaf, undefined, 'leaf');
    if (!proof || typeof proof !== 'object') return false;
    const { size, index, siblings } = proof;
    safeIndex(size, 'size');
    safeIndex(index, 'index');
    if (size <= 0 || index < 0 || index >= size) return false;
    if (!Array.isArray(siblings)) return false;
    if (!Array.isArray(proof.path)) return false;
    for (const s of siblings) abytes(s, DIGEST_LEN, 'sibling');
    // Derive the expected per-level structure from (size, index) and compare
    // entry by entry; never trust the proof's own markers or sibling count.
    let acc = leafHash(leaf);
    let consumed = 0;
    let width = 1;
    let level = 0;
    while (width < size) {
      let expectedSpan: number;
      const pos = Math.floor(index / width);
      if (pos % 2 === 1) {
        expectedSpan = width; // complete left subtree
      } else if ((pos + 1) * width < size) {
        expectedSpan = Math.min(width, size - (pos + 1) * width); // full or trailing fragment
      } else {
        expectedSpan = 0; // promoted
      }
      if (proof.path[level] !== expectedSpan) return false;
      if (expectedSpan !== 0) {
        if (consumed >= siblings.length) return false;
        const sibling = siblings[consumed++];
        acc = pos % 2 === 1 ? parentHash(sibling, acc) : parentHash(acc, sibling);
      }
      width *= 2;
      level += 1;
    }
    if (level !== proof.path.length) return false;
    return consumed === siblings.length && sameBytes(acc, root);
  } catch {
    return false;
  }
}
