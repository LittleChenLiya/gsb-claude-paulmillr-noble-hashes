/**
 * Chunked integrity chain ("chunk-chain").
 *
 * A tiny self-describing container for a sequence of payload chunks. Every block is:
 * - `seq`     : 8 bytes, big-endian unsigned 64-bit block sequence (starts at 0),
 * - `len`     : 4 bytes, big-endian unsigned 32-bit payload length,
 * - `payload` : `len` bytes,
 * - `digest`  : 32 bytes, `SHA256(prevDigest || seq || len || payload)`.
 *
 * The previous digest of the first block is 32 zero bytes. Each block's digest
 * binds its payload, its position, and all preceding blocks. A streaming parser
 * therefore detects missing blocks, reordered blocks, and tampered payloads.
 *
 * This module provides integrity, not authentication: anyone able to modify the
 * stream can recompute every digest. Authenticate the final digest out-of-band
 * (e.g. sign it with a real MAC / signature) if tampering by an active attacker
 * is in scope.
 *
 * @module
 * @example
 * Encode and parse a three-block chain.
 * ```ts
 * import { encodeChunkChain, ChunkChainParser } from '@noble/hashes/chunk-chain.js';
 * const payloads = [new Uint8Array([1]), new Uint8Array([2, 2]), new Uint8Array([3, 3, 3])];
 * const stream = encodeChunkChain(payloads).bytes;
 * const received: Uint8Array[] = [];
 * const parser = new ChunkChainParser((payload) => received.push(payload));
 * parser.update(stream); // bytes may arrive in any-sized fragments
 * parser.finish({ count: payloads.length, digest: parser.lastDigest });
 * ```
 */
import { sha256 } from './sha2.ts';
import { abytes, anumber, concatBytes, copyBytes, isBytes, type TArg, type TRet } from './utils.ts';

/** Default per-block payload cap: 1 MiB. */
export const DEFAULT_MAX_PAYLOAD_LENGTH: number = 1024 * 1024;

/** Fixed sizes of the wire-format pieces, in bytes. */
const SEQ_BYTES = 8;
const LEN_BYTES = 4;
const DIGEST_BYTES = 32;
const HEADER_BYTES = SEQ_BYTES + LEN_BYTES;
const _0n = /* @__PURE__ */ BigInt(0);
const _8n = /* @__PURE__ */ BigInt(8);
const _ffn = /* @__PURE__ */ BigInt(0xff);
const U64_MASK = /* @__PURE__ */ (() => (BigInt(1) << BigInt(64)) - BigInt(1))();

export type ChunkChainErrorCode =
  | 'invalid_arguments'
  | 'payload_too_large'
  | 'sequence_overflow'
  | 'sequence_mismatch'
  | 'digest_mismatch'
  | 'handler_error'
  | 'trailing_bytes'
  | 'count_mismatch'
  | 'final_digest_mismatch'
  | 'failed'
  | 'finished';

/**
 * Error raised for every chunk-chain failure. After such an error a parser is
 * permanently in the failed state and never delivers another payload.
 */
export class ChunkChainError extends Error {
  readonly code: ChunkChainErrorCode;
  constructor(code: ChunkChainErrorCode, message: string) {
    super('chunk-chain: ' + message);
    this.name = 'ChunkChainError';
    this.code = code;
  }
}

/** Validate a sequence number expressed as a bigint: unsigned 64-bit. */
function aseq(seq: bigint): bigint {
  if (typeof seq !== 'bigint')
    throw new ChunkChainError('invalid_arguments', 'expected bigint sequence, got ' + typeof seq);
  if (seq < _0n || seq > U64_MASK)
    throw new ChunkChainError('sequence_overflow', 'sequence out of u64 range: ' + seq);
  return seq;
}

/** Read an unsigned big-endian integer from bytes. */
function readBE(bytes: TArg<Uint8Array>, offset: number, length: number): bigint {
  let value = _0n;
  for (let i = 0; i < length; i++) value = (value << _8n) | BigInt(bytes[offset + i]);
  return value;
}

/** Write an unsigned big-endian bigint into exactly `length` bytes. */
function writeBE(value: bigint, length: number): TRet<Uint8Array> {
  const out = new Uint8Array(length);
  let rest = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(rest & _ffn);
    rest >>= _8n;
  }
  return out;
}

/** Constant-time 32-byte comparison. */
function digestEqual(a: TArg<Uint8Array>, b: TArg<Uint8Array>): boolean {
  let diff = 0;
  for (let i = 0; i < DIGEST_BYTES; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Encode a single block. The sequence is a `bigint` on purpose: block indices
 * above 2^53 must never round-trip through a JS `Number`.
 * @param seq - unsigned 64-bit sequence number (bigint)
 * @param payload - block payload
 * @param prevDigest - previous block digest (32 zero bytes for the first block)
 * @param maxPayloadLength - per-block payload upper bound
 * @returns Serialized block (header + payload + digest).
 * @throws {@link ChunkChainError} on invalid sequence or oversized payload.
 */
export function encodeChunkBlock(
  seq: bigint,
  payload: TArg<Uint8Array>,
  prevDigest: TArg<Uint8Array>,
  maxPayloadLength: number = DEFAULT_MAX_PAYLOAD_LENGTH
): TRet<Uint8Array> {
  aseq(seq);
  abytes(payload, undefined, 'payload');
  abytes(prevDigest, DIGEST_BYTES, 'prevDigest');
  anumber(maxPayloadLength, 'maxPayloadLength');
  if (payload.length > maxPayloadLength)
    throw new ChunkChainError(
      'payload_too_large',
      `payload length ${payload.length} exceeds limit ${maxPayloadLength}`
    );
  const seqBytes = writeBE(seq, SEQ_BYTES);
  const lenBytes = writeBE(BigInt(payload.length), LEN_BYTES);
  const digest = sha256(concatBytes(prevDigest, seqBytes, lenBytes, payload));
  return concatBytes(seqBytes, lenBytes, payload, digest);
}

/** Options for {@link ChunkChainEncoder}. */
export type ChunkChainEncoderOpts = {
  /** Per-block payload upper bound. Default: {@link DEFAULT_MAX_PAYLOAD_LENGTH}. */
  maxPayloadLength?: number;
  /** Sequence of the first block (bigint). Default: 0n. */
  initialSequence?: bigint;
};

/**
 * Stateful block encoder. Every {@link ChunkChainEncoder.push} appends one block
 * with the next sequence number and returns its serialized bytes.
 */
export class ChunkChainEncoder {
  private maxPayloadLength: number;
  private nextSeq: bigint;
  private prevDigest: Uint8Array = new Uint8Array(DIGEST_BYTES);
  /** Number of encoded blocks. */
  count: number = 0;

  constructor(opts: ChunkChainEncoderOpts = {}) {
    const max = opts.maxPayloadLength ?? DEFAULT_MAX_PAYLOAD_LENGTH;
    anumber(max, 'maxPayloadLength');
    if (max > 0xffffffff)
      throw new ChunkChainError('payload_too_large', 'limit exceeds u32 length');
    this.maxPayloadLength = max;
    this.nextSeq = opts.initialSequence === undefined ? _0n : aseq(opts.initialSequence);
  }

  /** Digest over all blocks encoded so far (32 zero bytes before the first block). */
  get lastDigest(): TRet<Uint8Array> {
    return copyBytes(this.prevDigest);
  }

  /** Next sequence number that {@link ChunkChainEncoder.push} will use (bigint). */
  get nextSequence(): bigint {
    return this.nextSeq;
  }

  /** Append one block and return its serialized bytes. */
  push(payload: TArg<Uint8Array>): TRet<Uint8Array> {
    abytes(payload, undefined, 'payload');
    if (payload.length > this.maxPayloadLength)
      throw new ChunkChainError(
        'payload_too_large',
        `payload length ${payload.length} exceeds limit ${this.maxPayloadLength}`
      );
    if (this.nextSeq > U64_MASK)
      throw new ChunkChainError('sequence_overflow', 'sequence out of u64 range');
    const block = encodeChunkBlock(this.nextSeq, payload, this.prevDigest, this.maxPayloadLength);
    this.prevDigest = block.subarray(block.length - DIGEST_BYTES);
    this.nextSeq++;
    this.count++;
    return block;
  }

  /** Encode every remaining payload block and return the concatenated stream. */
  finish(payloads: Iterable<TArg<Uint8Array>> = []): TRet<Uint8Array> {
    const blocks: TArg<Uint8Array>[] = [];
    for (const payload of payloads) blocks.push(this.push(payload));
    return concatBytes(...blocks);
  }
}

/**
 * Encode a whole chain of payloads, starting at sequence 0.
 * @param payloads - blocks to encode
 * @param maxPayloadLength - per-block payload upper bound
 * @returns Serialized stream plus `count` and final `digest`.
 */
export function encodeChunkChain(
  payloads: Iterable<Uint8Array>,
  maxPayloadLength: number = DEFAULT_MAX_PAYLOAD_LENGTH
): TRet<{ bytes: Uint8Array; count: number; digest: Uint8Array }> {
  const encoder = new ChunkChainEncoder({ maxPayloadLength });
  const bytes = encoder.finish(payloads);
  return { bytes, count: encoder.count, digest: encoder.lastDigest };
}

/** Payload delivery callback. A thrown error fails the parser permanently. */
export type ChunkChainHandler = (payload: Uint8Array, seq: bigint) => void;

/** Parameters the caller verifies at stream end. */
export type ChunkChainFinishOpts = {
  /** Expected total number of blocks. */
  count: number;
  /** Expected final digest (digest of the last delivered block). */
  digest: Uint8Array;
};

/** Result of a successful {@link ChunkChainParser.finish}. */
export type ChunkChainFinishResult = {
  count: number;
  digest: Uint8Array;
};

/**
 * Streaming, fragment-tolerant parser for a chunk-chain.
 *
 * Feed arbitrary byte fragments via {@link ChunkChainParser.update}; a payload is
 * delivered to the handler only when its whole block is present **and** its
 * digest verifies. The first error (bad sequence, bad digest, oversized length,
 * trailing bytes, ...) puts the parser in a permanent failed state, so blocks
 * after a tampered or missing one are never delivered.
 *
 * Declared payload lengths are checked against `maxPayloadLength` as soon as the
 * 12-byte header arrives: a forged huge `len` fails before any large allocation,
 * and memory never grows past the bytes actually received.
 */
export class ChunkChainParser {
  private handler: ChunkChainHandler;
  private maxPayloadLength: number;
  private chunks: Uint8Array[] = [];
  private buffered = 0;
  private prevDigest: Uint8Array = new Uint8Array(DIGEST_BYTES);
  private nextSeq: bigint = _0n;
  /** Number of verified, delivered blocks. */
  count = 0;
  private failed = false;
  private finished = false;
  private failCode: ChunkChainErrorCode | null = null;

  /**
   * @param handler - called once per fully verified block, in order.
   * @param maxPayloadLength - declared payload lengths above this fail immediately.
   */
  constructor(handler: ChunkChainHandler, maxPayloadLength: number = DEFAULT_MAX_PAYLOAD_LENGTH) {
    if (typeof handler !== 'function')
      throw new ChunkChainError('invalid_arguments', 'expected handler function');
    anumber(maxPayloadLength, 'maxPayloadLength');
    this.handler = handler;
    this.maxPayloadLength = maxPayloadLength;
  }

  /** Digest over the blocks delivered so far (32 zero bytes before the first one). */
  get lastDigest(): TRet<Uint8Array> {
    return copyBytes(this.prevDigest);
  }

  /** Whether the parser has entered the permanent failed state. */
  get isFailed(): boolean {
    return this.failed;
  }

  /** Failure code once {@link ChunkChainParser.isFailed} is true. */
  get errorCode(): ChunkChainErrorCode | null {
    return this.failCode;
  }

  /** Whether {@link ChunkChainParser.finish} completed successfully. */
  get isFinished(): boolean {
    return this.finished;
  }

  private fail(code: ChunkChainErrorCode, message: string): never {
    this.failed = true;
    this.failCode = code;
    this.chunks = [];
    this.buffered = 0;
    throw new ChunkChainError(code, message);
  }

  private ensureAlive(): void {
    if (this.failed) throw new ChunkChainError('failed', 'parser already failed: ' + this.failCode);
    if (this.finished) throw new ChunkChainError('finished', 'parser already finished');
  }

  /** Remove the first `length` buffered bytes, spanning queued fragments. */
  private consume(length: number): void {
    let remaining = length;
    while (remaining > 0) {
      const head = this.chunks[0];
      if (head.length <= remaining) {
        remaining -= head.length;
        this.chunks.shift();
      } else {
        this.chunks[0] = head.subarray(remaining);
        remaining = 0;
      }
    }
    this.buffered -= length;
  }

  /** Copy the first `length` buffered bytes into a fresh contiguous array. */
  private take(length: number): Uint8Array {
    const out = new Uint8Array(length);
    let offset = 0;
    for (const chunk of this.chunks) {
      const takeBytes = Math.min(chunk.length, length - offset);
      out.set(chunk.subarray(0, takeBytes), offset);
      offset += takeBytes;
      if (offset === length) break;
    }
    return out;
  }

  /** Feed a byte fragment. Any fragment size is accepted, including empty. */
  update(data: TArg<Uint8Array>): this {
    this.ensureAlive();
    abytes(data, undefined, 'data');
    if (data.length) {
      this.chunks.push(copyBytes(data));
      this.buffered += data.length;
    }
    for (;;) {
      if (this.buffered < HEADER_BYTES) break;
      const header = this.take(HEADER_BYTES);
      const seq = readBE(header, 0, SEQ_BYTES);
      const lenNum = Number(readBE(header, SEQ_BYTES, LEN_BYTES));
      if (seq !== this.nextSeq)
        this.fail('sequence_mismatch', `expected sequence ${this.nextSeq}, got ${seq}`);
      if (lenNum > this.maxPayloadLength)
        this.fail(
          'payload_too_large',
          `declared payload length ${lenNum} exceeds limit ${this.maxPayloadLength}`
        );
      const blockLen = HEADER_BYTES + lenNum + DIGEST_BYTES;
      if (this.buffered < blockLen) break;
      const block = this.take(blockLen);
      const payload = block.subarray(HEADER_BYTES, HEADER_BYTES + lenNum);
      const digest = block.subarray(HEADER_BYTES + lenNum);
      const seqBytes = header.subarray(0, SEQ_BYTES);
      const lenBytes = header.subarray(SEQ_BYTES);
      const expected = sha256(concatBytes(this.prevDigest, seqBytes, lenBytes, payload));
      if (!digestEqual(digest, expected))
        this.fail('digest_mismatch', `digest mismatch at sequence ${seq}`);
      const verifiedPayload = copyBytes(payload);
      this.prevDigest = copyBytes(digest);
      this.nextSeq++;
      this.count++;
      this.consume(blockLen);
      try {
        this.handler(verifiedPayload, seq);
      } catch (error) {
        this.fail('handler_error', 'handler threw at sequence ' + seq + ': ' + error);
      }
    }
    return this;
  }

  /**
   * End the stream and verify the caller's expected total block count and final
   * digest. Throws on any undelivered trailing/partial bytes or a mismatch.
   */
  finish(expected: ChunkChainFinishOpts): ChunkChainFinishResult {
    this.ensureAlive();
    if (
      typeof expected !== 'object' ||
      expected === null ||
      typeof (expected as ChunkChainFinishOpts).count !== 'number' ||
      !isBytes((expected as ChunkChainFinishOpts).digest)
    )
      throw new ChunkChainError(
        'invalid_arguments',
        'expected { count: number, digest: Uint8Array }'
      );
    anumber(expected.count, 'count');
    abytes(expected.digest, DIGEST_BYTES, 'digest');
    if (this.buffered !== 0)
      this.fail('trailing_bytes', `${this.buffered} undelivered byte(s) remain`);
    if (this.count !== expected.count)
      this.fail('count_mismatch', `expected ${expected.count} block(s), got ${this.count}`);
    if (!digestEqual(this.prevDigest, expected.digest))
      this.fail('final_digest_mismatch', 'final digest differs from expected');
    this.finished = true;
    return { count: this.count, digest: copyBytes(this.prevDigest) };
  }
}
