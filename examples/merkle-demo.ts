/**
 * Merkle tree demo: prints roots and verify results.
 * Run: node examples/merkle-demo.ts
 */
import { MerkleTree, verifyMerkleProof } from '../src/merkle.ts';
import { bytesToHex } from '../src/utils.ts';

const enc = new TextEncoder();
const t = new MerkleTree();
console.log('empty root :', bytesToHex(t.root));

['a', 'b', 'c'].forEach((s) => t.append(enc.encode(s)));
console.log('root (3)   :', bytesToHex(t.root), 'size:', t.size);

// Valid 3-leaf proof for leaf index 0.
const leaf0 = enc.encode('a');
const proof = t.proof(0);
console.log('valid proof ->', verifyMerkleProof(t.root, leaf0, proof));

// Tamper cases: index, size, leaf content, extra sibling.
console.log('wrong index ->', verifyMerkleProof(t.root, leaf0, { ...proof, index: 1 }));
console.log('wrong size  ->', verifyMerkleProof(t.root, leaf0, { ...proof, size: 4 }));
console.log('wrong leaf  ->', verifyMerkleProof(t.root, enc.encode('x'), proof));
console.log(
  'extra sibling ->',
  verifyMerkleProof(t.root, leaf0, {
    ...proof,
    siblings: [...proof.siblings, new Uint8Array(32)],
  })
);
