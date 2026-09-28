/**
 * Chunk integrity chain.
 *
 * Wire format of one block (all multi-byte integers are big-endian):
 *
 * - `sequence`: 8 bytes, unsigned 64-bit, starting at 0 and incremented per block
 * - `length`: 4 bytes, unsigned 32-bit payload length
 * - `payload`: `length` bytes
 * - `digest`: 32 bytes, `SHA-256(previousDigest || sequence || length || payload)`
 *
 * The previous digest of the first block is 32 zero bytes. A block is only delivered
 * to the caller after its digest verifies, so a missing, modified or reordered block
 * puts the stream into a permanent failed state. This is an integrity chain, not a
 * MAC: anyone able to modify blocks can also recompute every following digest, so it
 * must not be used to protect against an active attacker.
 * @module
 */
import { sha256 } from './sha2.ts';
import { abytes, anumber, type TArg, type TRet } from './utils.ts';

/** Length of a block digest in bytes (SHA-256 output). */
export const CHAIN_DIGEST_LEN: number = sha256.outputLen;
/** Length of the fixed block header: 8-byte sequence plus 4-byte payload length. */
export const CHAIN_HEADER_LEN: number = 12;
/** Default per-block payload length limit (1 MiB). */
export const CHAIN_DEFAULT_MAX_PAYLOAD: number = 1024 * 1024;

const U32_MAX = 0xffffffff;
const _0n = /* @__PURE__ */ BigInt(0);
const _1n = /* @__PURE__ */ BigInt(1);
const _64n = /* @__PURE__ */ BigInt(64);
const U64_MASK = (_1n << _64n) - _1n;

/** Error thrown by the chunk integrity chain, including parser stream failures. */
export class ChainError extends Error {
  constructor(message: string) {
    super('chain: ' + message);
    this.name = 'ChainError';
  }
}

export type ChainOpts = {
  /** Maximum payload length of a single block. Default: 1 MiB. */
  maxPayloadLength?: number;
  /** Sequence number of the first block, as a 64-bit bigint. Default: 0n. */
  startSequence?: bigint;
};

const parseOpts = (opts: ChainOpts = {}): { maxPayloadLength: number; startSequence: bigint } => {
  const maxPayloadLength =
    opts.maxPayloadLength === undefined ? CHAIN_DEFAULT_MAX_PAYLOAD : opts.maxPayloadLength;
  anumber(maxPayloadLength, 'maxPayloadLength');
  if (maxPayloadLength > U32_MAX)
    throw new RangeError('maxPayloadLength must fit in uint32, got ' + maxPayloadLength);
  const startSequence = opts.startSequence === undefined ? _0n : opts.startSequence;
  if (typeof startSequence !== 'bigint')
    throw new TypeError('startSequence expected bigint, got ' + typeof startSequence);
  if (startSequence < _0n || startSequence > U64_MASK)
    throw new RangeError('startSequence must be an unsigned 64-bit bigint, got ' + startSequence);
  return { maxPayloadLength, startSequence };
};

const writeHeader = (out: Uint8Array, offset: number, sequence: bigint, length: number): void => {
  const view = new DataView(out.buffer, out.byteOffset + offset, CHAIN_HEADER_LEN);
  view.setBigUint64(0, sequence, false);
  view.setUint32(8, length, false);
};

/** Block digest over `previousDigest || sequence || length || payload`. */
const blockDigest = (
  prevDigest: Uint8Array,
  sequence: bigint,
  length: number,
  payload: Uint8Array
): Uint8Array => {
  const header = new Uint8Array(CHAIN_HEADER_LEN);
  writeHeader(header, 0, sequence, length);
  return sha256.create().update(prevDigest).update(header).update(payload).digest();
};

/**
 * Streaming encoder for the chunk integrity chain.
 *
 * Sequence numbers are tracked as 64-bit `bigint`; appending a block whose sequence
 * would overflow uint64 throws instead of wrapping.
 * @example
 * Encode blocks.
 * ```ts
 * import { ChainEncoder } from '@noble/hashes/chain.js';
 * const enc = new ChainEncoder();
 * enc.add(new TextEncoder().encode('hello'));
 * enc.add(new TextEncoder().encode('world'));
 * const { bytes, count, digest } = enc.finish();
 * ```
 */
export class ChainEncoder {
  private maxPayloadLength: number;
  private sequence: bigint;
  private lastDigest: Uint8Array;
  private blocks: Uint8Array[];
  private finished = false;

  constructor(opts: ChainOpts = {}) {
    const parsed = parseOpts(opts);
    this.maxPayloadLength = parsed.maxPayloadLength;
    this.sequence = parsed.startSequence;
    this.lastDigest = new Uint8Array(CHAIN_DIGEST_LEN);
    this.blocks = [];
  }
  /** Number of blocks appended so far. */
  get count(): number {
    return this.blocks.length;
  }
  /** Digest of the last appended block; all-zero before the first block. */
  get digest(): Uint8Array {
    return this.lastDigest;
  }
  /**
   * Append one payload block and return its encoded bytes.
   * @param payload - block payload, at most `maxPayloadLength` bytes
   * @returns The encoded block (`header || payload || digest`).
   * @throws After `finish()`, on oversized payload or uint64 sequence overflow.
   */
  add(payload: TArg<Uint8Array>): TRet<Uint8Array> {
    if (this.finished) throw new ChainError('encoder already finished');
    const data = abytes(payload, undefined, 'payload');
    if (data.length > this.maxPayloadLength)
      throw new RangeError(
        'payload length ' + data.length + ' exceeds maxPayloadLength ' + this.maxPayloadLength
      );
    if (this.sequence > U64_MASK)
      throw new ChainError('sequence overflow: cannot encode block after uint64 exhaustion');
    const block = new Uint8Array(CHAIN_HEADER_LEN + data.length + CHAIN_DIGEST_LEN);
    writeHeader(block, 0, this.sequence, data.length);
    block.set(data, CHAIN_HEADER_LEN);
    const digest = blockDigest(this.lastDigest, this.sequence, data.length, data);
    block.set(digest, CHAIN_HEADER_LEN + data.length);
    this.blocks.push(block);
    this.lastDigest = digest;
    this.sequence++;
    return block as TRet<Uint8Array>;
  }
  /**
   * Finish encoding and concatenate every appended block.
   * @returns `bytes` of the whole stream plus its block `count` and final `digest`.
   */
  finish(): { bytes: TRet<Uint8Array>; count: number; digest: TRet<Uint8Array> } {
    if (this.finished) throw new ChainError('encoder already finished');
    this.finished = true;
    const total = this.blocks.reduce((sum, block) => sum + block.length, 0);
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const block of this.blocks) {
      bytes.set(block, offset);
      offset += block.length;
    }
    return {
      bytes: bytes as TRet<Uint8Array>,
      count: this.blocks.length,
      digest: this.lastDigest as TRet<Uint8Array>,
    };
  }
}

/**
 * One-shot helper: encode an array of payload blocks.
 * @param payloads - payload blocks in delivery order
 * @param opts - chain options
 * @returns Encoded `bytes`, block `count` and final chain `digest`.
 */
export const encodeChain = (
  payloads: TArg<Uint8Array[]>,
  opts: ChainOpts = {}
): { bytes: TRet<Uint8Array>; count: number; digest: TRet<Uint8Array> } => {
  if (!Array.isArray(payloads)) throw new TypeError('payloads expected array of Uint8Array');
  const enc = new ChainEncoder(opts);
  for (const payload of payloads) enc.add(payload);
  return enc.finish();
};

/** Queue of arbitrary byte fragments; bytes are only copied on read. */
class ByteStream {
  private chunks: Uint8Array[] = [];
  private offset = 0;
  private total = 0;

  get length(): number {
    return this.total;
  }
  push(chunk: Uint8Array): void {
    if (!chunk.length) return;
    this.chunks.push(chunk);
    this.total += chunk.length;
  }
  /** Copy exactly `out.length` bytes into `out`; caller ensures enough bytes remain. */
  readInto(out: Uint8Array): void {
    let pos = 0;
    while (pos < out.length) {
      const chunk = this.chunks[0];
      const take = Math.min(chunk.length - this.offset, out.length - pos);
      out.set(chunk.subarray(this.offset, this.offset + take), pos);
      pos += take;
      this.offset += take;
      this.total -= take;
      if (this.offset === chunk.length) {
        this.chunks.shift();
        this.offset = 0;
      }
    }
  }
  /** Copy up to `max` available bytes into a fresh buffer. */
  readCopy(max: number): Uint8Array {
    const out = new Uint8Array(Math.min(max, this.total));
    if (out.length) this.readInto(out);
    return out;
  }
}

const equalBytes = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
};

/**
 * Streaming parser for the chunk integrity chain.
 *
 * Feed arbitrary byte fragments with `update()`. A complete block whose sequence is
 * expected and whose digest verifies is delivered immediately through the `onBlock`
 * callback. Any failure (unexpected sequence, oversized declared payload, digest
 * mismatch or truncated/trailing bytes) is permanent: the parser stays in a failed
 * state and never delivers later blocks. Verify the expected total block count and
 * final digest with `end()`.
 *
 * This is not authenticated: a forged stream with every digest recomputed verifies.
 * @example
 * Parse an encoded stream fed one byte at a time.
 * ```ts
 * import { ChainParser } from '@noble/hashes/chain.js';
 * const blocks: Uint8Array[] = [];
 * const parser = new ChainParser((payload) => blocks.push(payload));
 * for (const byte of bytes) parser.update(new Uint8Array([byte]));
 * const { count, digest } = parser.end(3, expectedDigest);
 * ```
 */
export class ChainParser {
  private onBlock: (payload: Uint8Array) => void;
  private maxPayloadLength: number;
  private expectedSequence: bigint;
  private prevDigest: Uint8Array;
  private buffer = new ByteStream();
  private hashState: ReturnType<typeof sha256.create>;
  private stage: 'header' | 'payload' | 'digest' = 'header';
  private payloadLength = 0;
  private payload = new Uint8Array(0);
  private payloadOffset = 0;
  private count = 0;
  private failed = false;
  private failure = '';
  private ended = false;

  constructor(onBlock: (payload: Uint8Array) => void, opts: ChainOpts = {}) {
    if (typeof onBlock !== 'function') throw new TypeError('onBlock expected function');
    const parsed = parseOpts(opts);
    this.onBlock = onBlock;
    this.maxPayloadLength = parsed.maxPayloadLength;
    this.expectedSequence = parsed.startSequence;
    this.prevDigest = new Uint8Array(CHAIN_DIGEST_LEN);
    this.hashState = sha256.create();
  }
  /** Number of verified, delivered blocks so far. */
  get delivered(): number {
    return this.count;
  }
  /** Digest of the last delivered block; all-zero before the first block. */
  get digest(): Uint8Array {
    return this.prevDigest;
  }
  /** Whether the parser has not entered the permanent failed state. */
  get ok(): boolean {
    return !this.failed;
  }

  /** Feed an arbitrary byte fragment; complete, valid blocks fire `onBlock` synchronously. */
  update(chunk: TArg<Uint8Array>): this {
    if (this.ended) throw new ChainError('parser already ended');
    if (this.failed) return this;
    const data = abytes(chunk, undefined, 'chunk');
    this.buffer.push(data);
    while (!this.failed) {
      if (this.stage === 'header') {
        if (this.buffer.length < CHAIN_HEADER_LEN) break;
        const header = new Uint8Array(CHAIN_HEADER_LEN);
        this.buffer.readInto(header);
        const view = new DataView(header.buffer);
        const sequence = view.getBigUint64(0, false);
        if (sequence !== this.expectedSequence)
          return this.fail(
            'expected block sequence ' + this.expectedSequence + ', got ' + sequence
          );
        const length = view.getUint32(8, false);
        if (length > this.maxPayloadLength)
          return this.fail(
            'declared payload length ' + length + ' exceeds ' + this.maxPayloadLength
          );
        this.payloadLength = length;
        this.payload = new Uint8Array(length);
        this.payloadOffset = 0;
        this.hashState = sha256.create().update(this.prevDigest).update(header);
        this.stage = 'payload';
      }
      if (this.stage === 'payload') {
        if (this.buffer.length === 0) break;
        const slice = this.buffer.readCopy(this.payloadLength - this.payloadOffset);
        this.payload.set(slice, this.payloadOffset);
        this.hashState.update(slice);
        this.payloadOffset += slice.length;
        if (this.payloadOffset < this.payloadLength) break;
        this.stage = 'digest';
      }
      if (this.stage === 'digest') {
        if (this.buffer.length < CHAIN_DIGEST_LEN) break;
        const claimed = new Uint8Array(CHAIN_DIGEST_LEN);
        this.buffer.readInto(claimed);
        const actual = this.hashState.digest();
        if (!equalBytes(claimed, actual))
          return this.fail('digest mismatch at block sequence ' + this.expectedSequence);
        this.prevDigest = actual;
        this.count++;
        this.expectedSequence++;
        this.stage = 'header';
        this.onBlock(this.payload);
      }
    }
    return this;
  }

  /**
   * Finish the stream and verify totals.
   * @param expectedCount - total number of blocks the caller expects
   * @param expectedDigest - final chain digest (digest of the last block)
   * @returns Delivered block `count` and final `digest`.
   * @throws On any prior parse failure, truncated/undelivered bytes, wrong count or digest.
   */
  end(
    expectedCount: number,
    expectedDigest: TArg<Uint8Array>
  ): { count: number; digest: TRet<Uint8Array> } {
    if (this.ended) throw new ChainError('parser already ended');
    this.ended = true;
    anumber(expectedCount, 'expectedCount');
    const want = abytes(expectedDigest, CHAIN_DIGEST_LEN, 'expectedDigest');
    if (this.failed) throw new ChainError('stream failed: ' + this.failure);
    if (this.stage !== 'header' || this.buffer.length !== 0)
      throw new ChainError('truncated stream: undelivered bytes remain at end');
    if (this.count !== expectedCount)
      throw new ChainError('expected ' + expectedCount + ' blocks, got ' + this.count);
    if (!equalBytes(this.prevDigest, want)) throw new ChainError('final digest mismatch');
    return { count: this.count, digest: this.prevDigest as TRet<Uint8Array> };
  }

  private fail(message: string): this {
    this.failed = true;
    this.failure = message;
    throw new ChainError(message);
  }
}
