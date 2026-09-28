import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import {
  CHAIN_DEFAULT_MAX_PAYLOAD,
  ChainEncoder,
  ChainError,
  ChainParser,
  encodeChain,
} from '../src/chain.ts';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '../src/utils.ts';
import { sha256 } from '../src/sha2.ts';

const P0 = utf8ToBytes('alpha');
const P1 = utf8ToBytes('beta-block');
const P2 = Uint8Array.from([0, 1, 2, 255]);
const PAYLOADS = [P0, P1, P2];

// Fixed wire vectors: SHA-256(prevDigest || seq_be64 || len_be32 || payload), prevDigest = 0.
const BLOCK0 =
  '000000000000000000000005616c706861bcbf656ecfc046c367511a054c256750c4892744d9f1010a833bb6175d20bbba';
const BLOCK1 =
  '00000000000000010000000a626574612d626c6f636ba51406a0c0520d0aef41bd6515afdaca0d13f7d6aa5762e5a5c3dbb7999b0b1b';
const BLOCK2 =
  '000000000000000200000004000102ff1d9d559af8070043597b06aaabadfd031877dcdb21ab431ba11f16f9787a237d';
const FINAL_DIGEST = '1d9d559af8070043597b06aaabadfd031877dcdb21ab431ba11f16f9787a237d';
const EMPTY_BLOCK =
  '00000000000000000000000085759b3811ff7dc47b03792ac85317be51431a3f9e01dcafce317ed736a391b0';
const EMPTY_DIGEST = '85759b3811ff7dc47b03792ac85317be51431a3f9e01dcafce317ed736a391b0';
const BIGSEQ = 2n ** 53n + 1n; // beyond Number.MAX_SAFE_INTEGER
const BIGSEQ_BLOCK =
  '00200000000000010000000178a65d76a9a195337a0a8df15eebe7339918faecb8ada6b2439848d2b8fb4f22a8';
const BIGSEQ_DIGEST = 'a65d76a9a195337a0a8df15eebe7339918faecb8ada6b2439848d2b8fb4f22a8';

const encodeAll = () => {
  const enc = new ChainEncoder();
  const blocks = PAYLOADS.map((p) => enc.add(p));
  return { blocks, result: enc.finish() };
};

// Deterministically split bytes at varied boundaries (incl. 1-byte fragments).
function* fragments(bytes: Uint8Array): Generator<Uint8Array> {
  const sizes = [1, 3, 7, 13, 1, 2, 32, 5];
  let pos = 0;
  let i = 0;
  while (pos < bytes.length) {
    const size = Math.min(sizes[i++ % sizes.length], bytes.length - pos);
    yield bytes.subarray(pos, pos + size);
    pos += size;
  }
}

describe('chain fixed vectors', () => {
  it('encoder output matches fixed block/final-digest vectors', () => {
    const { blocks, result } = encodeAll();
    eql(blocks.map(bytesToHex), [BLOCK0, BLOCK1, BLOCK2]);
    eql(bytesToHex(result.bytes), BLOCK0 + BLOCK1 + BLOCK2);
    eql(result.count, 3);
    eql(bytesToHex(result.digest), FINAL_DIGEST);
    eql(CHAIN_DEFAULT_MAX_PAYLOAD, 1024 * 1024);
  });
  it('empty-payload block has its fixed digest', () => {
    const enc = new ChainEncoder();
    const block = enc.add(new Uint8Array(0));
    eql(bytesToHex(block), EMPTY_BLOCK);
    eql(bytesToHex(enc.finish().digest), EMPTY_DIGEST);
  });
  it('parses the fixed vector from a single fragment', () => {
    const delivered: Uint8Array[] = [];
    const parser = new ChainParser((payload) => delivered.push(payload));
    parser.update(hexToBytes(BLOCK0 + BLOCK1 + BLOCK2));
    eql(delivered, PAYLOADS);
    const res = parser.end(3, hexToBytes(FINAL_DIGEST));
    eql(res.count, 3);
    eql(bytesToHex(res.digest), FINAL_DIGEST);
  });
});

describe('chain streaming', () => {
  it('delivers exact order and content when fed one byte at a time', () => {
    const { result } = encodeAll();
    const delivered: Uint8Array[] = [];
    const parser = new ChainParser((payload) => delivered.push(payload));
    for (const byte of result.bytes) parser.update(Uint8Array.from([byte]));
    eql(delivered.length, 3);
    eql(delivered, PAYLOADS);
    eql(parser.delivered, 3);
    eql(parser.ok, true);
    eql(bytesToHex(parser.digest), FINAL_DIGEST);
    parser.end(3, result.digest);
  });
  it('handles arbitrary fragment boundaries across headers, payloads and digests', () => {
    const { result } = encodeAll();
    const delivered: Uint8Array[] = [];
    const parser = new ChainParser((payload) => delivered.push(payload));
    for (const fragment of fragments(result.bytes)) parser.update(fragment);
    eql(delivered, PAYLOADS);
    parser.end(3, result.digest);
  });
  it('supports the one-shot encodeChain helper', () => {
    const result = encodeChain(PAYLOADS);
    eql(result.count, 3);
    eql(bytesToHex(result.digest), FINAL_DIGEST);
    const delivered: Uint8Array[] = [];
    const parser = new ChainParser((payload) => delivered.push(payload));
    parser.update(result.bytes);
    eql(delivered, PAYLOADS);
    parser.end(3, result.digest);
  });
  it('accepts a zero-block stream against the all-zero digest', () => {
    const enc = new ChainEncoder();
    const result = enc.finish();
    eql(result.count, 0);
    eql(result.bytes.length, 0);
    const parser = new ChainParser(() => {
      throw new Error('callback must not fire');
    });
    const res = parser.end(0, new Uint8Array(32));
    eql(res.count, 0);
  });
});
describe('chain tamper detection', () => {
  const failing = (
    mutate: (bytes: Uint8Array, blocks: Uint8Array[]) => Uint8Array,
    prefixLen: number,
    opts = {}
  ) => {
    const { blocks, result } = encodeAll();
    const bytes = mutate(new Uint8Array(result.bytes), blocks);
    const delivered: Uint8Array[] = [];
    const parser = new ChainParser((payload) => delivered.push(payload), opts);
    throws(() => {
      for (const fragment of fragments(bytes)) parser.update(fragment);
    }, ChainError);
    eql(parser.ok, false);
    eql(delivered, PAYLOADS.slice(0, prefixLen));
    // Failed state is terminal: more input is ignored, end() reports the failure.
    parser.update(hexToBytes(BLOCK2));
    eql(parser.delivered, prefixLen);
    throws(() => parser.end(3, hexToBytes(FINAL_DIGEST)), ChainError);
  };

  it('modified payload: fails at that block and keeps the verified prefix', () => {
    failing((bytes) => {
      // Block 1 payload starts after block 0 (49B) + its own 12B header.
      bytes[49 + 12] ^= 0xff;
      return bytes;
    }, 1);
  });
  it('swapped blocks: sequence jump is detected after the delivered prefix', () => {
    failing((_bytes, blocks) => concatBytes(blocks[0], blocks[2], blocks[1]), 1);
  });
  it('deleted last block: delivers the prefix but end() rejects the count', () => {
    const { blocks } = encodeAll();
    const delivered: Uint8Array[] = [];
    const parser = new ChainParser((payload) => delivered.push(payload));
    parser.update(concatBytes(blocks[0], blocks[1]));
    eql(delivered, [P0, P1]);
    throws(() => parser.end(3, hexToBytes(FINAL_DIGEST)), /expected 3 blocks, got 2/);
  });
  it('forged oversized length: rejected before any payload buffer of that size exists', () => {
    failing(
      (bytes) => {
        // Block 2 starts after blocks 0 (49B) and 1 (54B); forge its uint32 length.
        const view = new DataView(bytes.buffer, bytes.byteOffset + 49 + 54 + 8, 4);
        view.setUint32(0, 0xffffffff, false);
        return bytes;
      },
      2,
      { maxPayloadLength: 1024 }
    );
  });
  it('truncated mid-block bytes leave a permanent failure', () => {
    const { result } = encodeAll();
    const truncated = result.bytes.subarray(0, result.bytes.length - 10);
    const delivered: Uint8Array[] = [];
    const parser = new ChainParser((payload) => delivered.push(payload));
    parser.update(truncated);
    eql(delivered, [P0, P1]);
    throws(() => parser.end(3, result.digest), /truncated stream/);
  });
  it('wrong final digest is rejected at end', () => {
    const { result } = encodeAll();
    const parser = new ChainParser(() => {});
    parser.update(result.bytes);
    const wrong = new Uint8Array(32);
    wrong[0] = 1;
    throws(() => parser.end(3, wrong), /final digest mismatch/);
  });
  it('wrong declared block count is rejected at end', () => {
    const { result } = encodeAll();
    const parser = new ChainParser(() => {});
    parser.update(result.bytes);
    throws(() => parser.end(2, result.digest), /expected 2 blocks, got 3/);
  });
});
describe('chain limits and options', () => {
  it('encoder rejects oversized payloads and invalid options', () => {
    const enc = new ChainEncoder({ maxPayloadLength: 4 });
    enc.add(Uint8Array.from([1, 2, 3, 4]));
    throws(() => enc.add(Uint8Array.from([1, 2, 3, 4, 5])), RangeError);
    throws(() => new ChainEncoder({ maxPayloadLength: -1 }), RangeError);
    throws(() => new ChainEncoder({ maxPayloadLength: 2 ** 32 }), RangeError);
    throws(() => new ChainEncoder({ startSequence: 2n ** 64n }), RangeError);
    throws(() => new ChainEncoder({ startSequence: 1 as any }), TypeError);
    throws(() => new ChainParser(null as any), TypeError);
  });
  it('parser rejects a declared length above the limit without allocating it', () => {
    // Claim 1 MiB + 1 in a header while sending only a handful of trailing bytes:
    // a parser that allocated on the declared length could not recover instantly.
    const claimed = CHAIN_DEFAULT_MAX_PAYLOAD + 1;
    const header = new Uint8Array(12);
    const view = new DataView(header.buffer);
    view.setBigUint64(0, 0n, false);
    view.setUint32(8, claimed, false);
    const parser = new ChainParser(() => {
      throw new Error('no block should be delivered');
    });
    throws(() => parser.update(concatBytes(header, Uint8Array.from([1, 2, 3]))), ChainError);
    eql(parser.delivered, 0);
    eql(parser.ok, false);
  });
  it('detects uint64 sequence overflow at the encoder', () => {
    const enc = new ChainEncoder({ startSequence: 2n ** 64n - 1n });
    enc.add(utf8ToBytes('last'));
    eql(enc.count, 1);
    throws(() => enc.add(utf8ToBytes('overflow')), /sequence overflow/);
  });
  it('rejects reuse after finish/end', () => {
    const enc = new ChainEncoder();
    enc.add(P0);
    enc.finish();
    throws(() => enc.add(P1), ChainError);
    throws(() => enc.finish(), ChainError);
    const parser = new ChainParser(() => {});
    parser.end(0, new Uint8Array(32));
    throws(() => parser.update(P0), ChainError);
    throws(() => parser.end(0, new Uint8Array(32)), ChainError);
  });
});

describe('chain 64-bit sequences', () => {
  it('encodes and verifies a sequence above 2**53 without Number precision loss', () => {
    const enc = new ChainEncoder({ startSequence: BIGSEQ });
    const block = enc.add(utf8ToBytes('x'));
    eql(bytesToHex(block), BIGSEQ_BLOCK);
    const result = enc.finish();
    eql(bytesToHex(result.digest), BIGSEQ_DIGEST);
    // First 8 bytes of the wire block are exactly 2**53 + 1.
    eql(new DataView(block.buffer, block.byteOffset, 8).getBigUint64(0, false), BIGSEQ);

    const delivered: Uint8Array[] = [];
    const parser = new ChainParser((payload) => delivered.push(payload), {
      startSequence: BIGSEQ,
    });
    for (const byte of block) parser.update(Uint8Array.from([byte]));
    eql(delivered, [utf8ToBytes('x')]);
    parser.end(1, result.digest);
  });
  it('a default parser starting at sequence 0 rejects the high-sequence block', () => {
    const parser = new ChainParser(() => {
      throw new Error('no block should be delivered');
    });
    throws(() => parser.update(hexToBytes(BIGSEQ_BLOCK)), /expected block sequence 0/);
    eql(parser.delivered, 0);
  });
});
// Build one raw block for the integrity-only demonstration.
const rawBlock = (
  prevDigest: Uint8Array,
  sequence: bigint,
  payload: Uint8Array
): { block: Uint8Array; digest: Uint8Array } => {
  const header = new Uint8Array(12);
  const view = new DataView(header.buffer);
  view.setBigUint64(0, sequence, false);
  view.setUint32(8, payload.length, false);
  const digest = sha256.create().update(prevDigest).update(header).update(payload).digest();
  return { block: concatBytes(header, payload, digest), digest };
};

describe('chain is integrity-only (not authenticated)', () => {
  it('a modified stream with digests recomputed afterwards verifies', () => {
    const enc = new ChainEncoder();
    const block0 = enc.add(P0);
    const digest0 = enc.digest;

    // Tamper with block 1's payload, then honestly recompute block 1 and block 2 digests.
    const changed = utf8ToBytes('beta-CHANGED');
    const one = rawBlock(digest0, 1n, changed);
    const two = rawBlock(one.digest, 2n, P2);

    const delivered: Uint8Array[] = [];
    const parser = new ChainParser((payload) => delivered.push(payload));
    parser.update(concatBytes(block0, one.block, two.block));
    eql(delivered, [P0, changed, P2]);
    // The parser cannot distinguish this from an honest stream.
    parser.end(3, two.digest);
  });
});

it.runWhen(import.meta.url);
