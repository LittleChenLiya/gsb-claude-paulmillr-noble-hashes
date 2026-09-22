/**
 * Demo: incremental SHA-256 Merkle tree.
 * Prints roots and proof verification results. Run: node examples/merkle.ts
 */
import { MerkleTree, verifyProof } from '../src/merkle.ts';
import { bytesToHex, utf8ToBytes } from '../src/utils.ts';

const leaves = [0, 1, 2, 3, 4].map((i) => utf8ToBytes('leaf-' + i));

for (const size of [0, 1, 2, 3, 5]) {
  const tree = new MerkleTree();
  for (let i = 0; i < size; i++) tree.append(leaves[i]);
  const root = bytesToHex(tree.root());
  console.log(`size=${size} root=${root}`);
  for (let i = 0; i < size; i++) {
    const ok = verifyProof(tree.root(), leaves[i], tree.proof(i));
    console.log(`  proof leaf[${i}] valid=${ok}`);
  }
}

// Tamper demo on the 3-leaf tree
const tree = new MerkleTree();
for (let i = 0; i < 3; i++) tree.append(leaves[i]);
const root = tree.root();
const proof = tree.proof(1);
console.log('valid proof:', verifyProof(root, leaves[1], proof));
console.log('tampered index:', verifyProof(root, leaves[1], { ...proof, leafIndex: 2 }));
console.log('tampered size:', verifyProof(root, leaves[1], { ...proof, treeSize: 5 }));
console.log('tampered leaf:', verifyProof(root, utf8ToBytes('leaf-x'), proof));
console.log(
  'extra sibling:',
  verifyProof(root, leaves[1], { ...proof, siblings: [...proof.siblings, new Uint8Array(32)] })
);
