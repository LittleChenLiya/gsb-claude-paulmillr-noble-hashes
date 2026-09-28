import { describe, it } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import {
  ChunkChainEncoder,
  ChunkChainError,
  ChunkChainParser,
  DEFAULT_MAX_PAYLOAD_LENGTH,
  encodeChunkBlock,
  encodeChunkChain,
} from '../src/chunk-chain.ts';
import { sha256 } from '../src/sha2.ts';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '../src/utils.ts';

const PAYLOADS = [utf8ToBytes('alpha'), utf8ToBytes('bravo'), utf8ToBytes('charlie')];

// Fixed vectors: sha256(prevDigest || seqBE64 || lenBE32 || payload), first prevDigest = 32 zeros.
const VECTORS = {
  digests: [
    'bcbf656ecfc046c367511a054c256750c4892744d9f1010a833bb6175d20bbba',
    'a337e8ffc433813bcfaa5072e886a7cf620661ad79bd791f78ce9e6041a2d629',
    '46c4184d12850b0cf76c8934f56c3950de536413a94a84627dd14fdb23fbe22b',
  ],
  stream:
    '000000000000000000000005616c706861' +
    'bcbf656ecfc046c367511a054c256750c4892744d9f1010a833bb6175d20bbba' +
    '000000000000000100000005627261766f' +
    'a337e8ffc433813bcfaa5072e886a7cf620661ad79bd791f78ce9e6041a2d629' +
    '000000000000000200000007636861726c6965' +
    '46c4184d12850b0cf76c8934f56c3950de536413a94a84627dd14fdb23fbe22b',
  // Block with seq = 2^53 + 1 (not representable as a JS Number), payload 0xdead.
  bigSeq: 9007199254740993n,
  bigSeqBlock:
    '0020000000000001' +
    '00000002' +
    'dead' +
    '81e9cfd2f45c9ca359aa3f76b6aaf7ba8a9cc7c88424a3c1751a2838fb77d85c',
};

const BLOCK_SIZES = PAYLOADS.map((p) => 12 + p.length + 32);

function stream(): Uint8Array {
  return encodeChunkChain(PAYLOADS).bytes;
}

function parseIn(
  bytes: Uint8Array,
  sizes: number[]
): { delivered: Uint8Array[]; seqs: bigint[]; parser: ChunkChainParser } {
  const delivered: Uint8Array[] = [];
  const seqs: bigint[] = [];
  const parser = new ChunkChainParser((payload, seq) => {
    delivered.push(payload);
    seqs.push(seq);
  });
  let offset = 0;
  let i = 0;
  while (offset < bytes.length) {
    const size = sizes[i++ % sizes.length];
    parser.update(bytes.subarray(offset, offset + size));
    offset += size;
  }
  return { delivered, seqs, parser };
}

function expectFail(fn: () => void, code: string) {
  let error: any;
  try {
    fn();
  } catch (e) {
    error = e;
  }
  if (!error) throw new Error('expected ChunkChainError ' + code + ', got no error');
  if (!(error instanceof ChunkChainError) || error.code !== code)
    throw new Error('expected ChunkChainError ' + code + ', got ' + error);
}

describe('chunk-chain', () => {
  it('fixed vectors', () => {
    const out = encodeChunkChain(PAYLOADS);
    eql(out.count, 3);
    eql(bytesToHex(out.bytes), VECTORS.stream);
    eql(bytesToHex(out.digest), VECTORS.digests[2]);
    const encoder = new ChunkChainEncoder();
    for (let i = 0; i < PAYLOADS.length; i++) {
      encoder.push(PAYLOADS[i]);
      eql(bytesToHex(encoder.lastDigest), VECTORS.digests[i]);
    }
    eql(encoder.count, 3);
  });

  it('parses byte-by-byte and delivers in order', () => {
    const { delivered, seqs, parser } = parseIn(stream(), [1]);
    eql(delivered, PAYLOADS);
    eql(seqs, [0n, 1n, 2n]);
    const res = parser.finish({ count: 3, digest: hexToBytes(VECTORS.digests[2]) });
    eql(res.count, 3);
    eql(parser.isFinished, true);
    eql(parser.isFailed, false);
  });

  it('parses arbitrary fragment sizes', () => {
    for (const sizes of [[2], [7, 13, 1, 64], [149], [5, 3, 11, 17, 23, 41]]) {
      const { delivered, parser } = parseIn(stream(), sizes);
      eql(delivered, PAYLOADS);
      parser.finish({ count: 3, digest: hexToBytes(VECTORS.digests[2]) });
    }
  });

  it('detects tampered payload and keeps delivered prefix', () => {
    const bytes = stream();
    bytes[BLOCK_SIZES[0] + 12] ^= 0x01; // flip first payload byte of block 1
    const { delivered, parser } = (() => {
      const delivered: Uint8Array[] = [];
      const parser = new ChunkChainParser((p) => delivered.push(p));
      expectFail(() => parser.update(bytes), 'digest_mismatch');
      return { delivered, parser };
    })();
    eql(delivered, [PAYLOADS[0]]);
    eql(parser.isFailed, true);
    // Failed state is permanent: no further updates, no more deliveries.
    expectFail(() => parser.update(stream()), 'failed');
    eql(delivered, [PAYLOADS[0]]);
  });

  it('detects swapped blocks and keeps delivered prefix', () => {
    const bytes = stream();
    const b0 = bytes.subarray(0, BLOCK_SIZES[0]);
    const b1 = bytes.subarray(BLOCK_SIZES[0], BLOCK_SIZES[0] + BLOCK_SIZES[1]);
    const b2 = bytes.subarray(BLOCK_SIZES[0] + BLOCK_SIZES[1]);
    const swapped = concatBytes(b0, b2, b1);
    const delivered: Uint8Array[] = [];
    const parser = new ChunkChainParser((p) => delivered.push(p));
    expectFail(() => parser.update(swapped), 'sequence_mismatch');
    eql(delivered, [PAYLOADS[0]]);
    eql(parser.errorCode, 'sequence_mismatch');
  });

  it('detects dropped last block at finish', () => {
    const bytes = stream().subarray(0, BLOCK_SIZES[0] + BLOCK_SIZES[1]);
    const { delivered, parser } = parseIn(bytes, [3]);
    eql(delivered, [PAYLOADS[0], PAYLOADS[1]]);
    expectFail(
      () => parser.finish({ count: 3, digest: hexToBytes(VECTORS.digests[2]) }),
      'count_mismatch'
    );
    eql(parser.isFailed, true);
  });

  it('detects truncated final block at finish', () => {
    const bytes = stream().subarray(0, stream().length - 5);
    const { delivered, parser } = parseIn(bytes, [8]);
    eql(delivered, [PAYLOADS[0], PAYLOADS[1]]);
    expectFail(
      () => parser.finish({ count: 3, digest: hexToBytes(VECTORS.digests[2]) }),
      'trailing_bytes'
    );
  });

  it('rejects forged huge length before buffering', () => {
    const bytes = stream();
    const b0 = bytes.subarray(0, BLOCK_SIZES[0]);
    const forgedHeader = hexToBytes('0000000000000001' + 'ffffffff');
    const delivered: Uint8Array[] = [];
    const parser = new ChunkChainParser((p) => delivered.push(p));
    parser.update(b0);
    eql(delivered, [PAYLOADS[0]]);
    // Fails on the 12-byte header alone; no payload bytes were ever sent.
    expectFail(() => parser.update(forgedHeader), 'payload_too_large');
    eql(delivered, [PAYLOADS[0]]);
  });

  it('encodes sequences above 2^53 without Number precision loss', () => {
    // Number() cannot hold the sequence: 2^53+1 rounds down to 2^53.
    eql(Number(VECTORS.bigSeq), Number(2n ** 53n));
    eql(Number(VECTORS.bigSeq) === Number(VECTORS.bigSeq - 1n), true);
    const block = encodeChunkBlock(VECTORS.bigSeq, hexToBytes('dead'), new Uint8Array(32));
    eql(bytesToHex(block), VECTORS.bigSeqBlock);
    // Independently recompute the digest from the spec formula.
    const expected = sha256(
      concatBytes(
        new Uint8Array(32),
        hexToBytes('0020000000000001'),
        hexToBytes('00000002'),
        hexToBytes('dead')
      )
    );
    eql(bytesToHex(block.subarray(block.length - 32)), bytesToHex(expected));
    // Streaming encoder starting at a huge sequence.
    const encoder = new ChunkChainEncoder({ initialSequence: VECTORS.bigSeq });
    eql(encoder.nextSequence, VECTORS.bigSeq);
    const encoded = encoder.push(hexToBytes('dead'));
    eql(bytesToHex(encoded), VECTORS.bigSeqBlock);
  });

  it('encoder enforces payload cap and sequence overflow', () => {
    const encoder = new ChunkChainEncoder({ maxPayloadLength: 4 });
    expectFail(() => encoder.push(new Uint8Array(5)), 'payload_too_large');
    expectFail(
      () =>
        encodeChunkBlock(0n, new Uint8Array(DEFAULT_MAX_PAYLOAD_LENGTH + 1), new Uint8Array(32)),
      'payload_too_large'
    );
    expectFail(
      () => encodeChunkBlock(1n << 64n, new Uint8Array(0), new Uint8Array(32)),
      'sequence_overflow'
    );
    expectFail(
      () => encodeChunkBlock(-1n, new Uint8Array(0), new Uint8Array(32)),
      'sequence_overflow'
    );
    const last = new ChunkChainEncoder({ initialSequence: (1n << 64n) - 1n });
    last.push(new Uint8Array(0)); // seq 2^64-1 is still valid
    expectFail(() => last.push(new Uint8Array(0)), 'sequence_overflow');
  });

  it('finish verifies count and final digest', () => {
    const { parser } = parseIn(stream(), [16]);
    expectFail(
      () => parser.finish({ count: 2, digest: hexToBytes(VECTORS.digests[2]) }),
      'count_mismatch'
    );
    const { parser: parser2 } = parseIn(stream(), [16]);
    expectFail(
      () => parser2.finish({ count: 3, digest: hexToBytes(VECTORS.digests[1]) }),
      'final_digest_mismatch'
    );
  });

  it('handles empty chain', () => {
    const out = encodeChunkChain([]);
    eql(out.count, 0);
    eql(out.bytes.length, 0);
    const parser = new ChunkChainParser(() => {
      throw new Error('must not deliver');
    });
    parser.update(new Uint8Array(0));
    const res = parser.finish({ count: 0, digest: new Uint8Array(32) });
    eql(res.count, 0);
  });

  it('fails permanently when the handler throws', () => {
    const parser = new ChunkChainParser(() => {
      throw new Error('boom');
    });
    expectFail(() => parser.update(stream()), 'handler_error');
    eql(parser.isFailed, true);
    expectFail(() => parser.update(stream()), 'failed');
  });

  it('validates constructor and update arguments', () => {
    throws(() => new ChunkChainParser(null as any));
    throws(() => new ChunkChainParser(() => {}, -1));
    const parser = new ChunkChainParser(() => {});
    throws(() => parser.update('nope' as any));
    throws(() => parser.finish({ count: 0, digest: new Uint8Array(31) }));
  });
});

it.runWhen(import.meta.url);
