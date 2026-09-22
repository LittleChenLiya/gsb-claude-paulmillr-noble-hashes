# Merkle tree: format & complexity

Append-only SHA-256 Merkle tree from `@noble/hashes/merkle.js`. Pure JS,
`Uint8Array` only, no Node-specific crypto APIs (works in browsers and other
JS runtimes).

## Hashing rules

All hashes are SHA-256 (32 bytes), with one-byte domain separation:

- leaf: `H(0x00 || data)`
- parent: `H(0x01 || left || right)`
- empty tree root: `H('')`, exported as `EMPTY_MERKLE_ROOT`

When a level contains an odd number of nodes, the last node is **promoted**
to the next level unchanged (never copied or hashed against itself).

`append(data)` hashes `data` immediately and never stores the raw bytes;
mutating the caller's buffer afterwards cannot affect the tree.

## API

```typescript
const tree = new MerkleTree();
tree.append(a); // chainable, returns `this`
tree.size; // number of leaves (safe integer)
tree.root; // 32-byte Uint8Array (defensive copy)
const proof = tree.proof(i);
verifyMerkleProof(root, leafBytes, proof); // boolean, never throws
```

## Proof format

```typescript
type MerkleProof = {
  size: number; // tree size when the proof was made
  index: number; // zero-based leaf index
  path: number[]; // one entry per level, leaf-to-root
  siblings: Uint8Array[]; // 32-byte digest per nonzero path entry
};
```

Levels are counted from `0` (leaf level); level `k` groups nodes spanning
`2^k` leaves. `path[k]` describes the sibling of the proof node at level `k`:

- `2^k` — sibling is a complete subtree (`width`);
- a smaller positive value — sibling is a promoted trailing fragment and
  spans that many leaves;
- `0` — the node is promoted at this level and has no sibling.

`siblings` contains exactly the digests for nonzero `path` entries, in order.

Example, size 3 (`[a, b, c]`, `p = H(0x01||a'||b')`, root `H(0x01||p||c')`):

| index | path     | siblings                           |
| ----- | -------- | ---------------------------------- |
| 0     | `[2, 0]` | `b'` folded to `p`, c promoted     |
| 1     | `[2, 0]` | `a'` folded to `p`, c promoted     |
| 2     | `[0, 3]` | fragment `{a,b}` (`p`) on the left |

(`x'` denotes `H(0x00||x)`.)

## Verification

`verifyMerkleProof(root, leaf, proof)` derives the entire level structure
solely from `proof.size` and `proof.index`, then:

1. validates that `size`/`index` are safe integers with `0 <= index < size`;
2. recomputes the expected `path` (direction, fragment span, promoted
   levels) and compares it entry by entry with `proof.path`;
3. requires exactly one 32-byte `siblings` digest per nonzero entry — an
   extra sibling, missing sibling, or wrong-length digest rejects the proof
   immediately, regardless of whether some other fold reaches `root`;
4. folds `H(0x00||leaf)` with the siblings in the derived directions and
   compares the result with `root` in constant time (per 32-byte digest).

Malformed arguments return `false` instead of throwing.

## Complexity

Let `n` be the number of leaves, `h = ceil(log2(n))`.

| Operation                | Time                       | Extra memory               |
| ------------------------ | -------------------------- | -------------------------- |
| `append(data)`           | O(1) amortized, O(h) worst | O(h) for the carry chain   |
| `root`                   | O(h), cached after append  | O(1)                       |
| `proof(index)`           | O(h)                       | O(h) digests               |
| `verifyMerkleProof(...)` | O(h)                       | O(h)                       |
| Tree instance            | —                          | O(n) digests (~2n entries) |

The stored `levels[k]` arrays hold roots of complete `2^k`-sized subtrees
(the frontier plus its carry history). The root folds the last (odd) node of
each level in low-to-high order; trailing-fragment siblings that are not
stored are rebuilt from those level arrays in O(h), so proofs never rescan
leaves.
