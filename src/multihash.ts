/**
 * Multi-hash combiner: feeds the same bytes into several hash algorithms at once.
 * Also provides an async byte-iterator adapter with cleanup on cancel / error.
 * @module
 */
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { abytes, type Hash, type TArg, type TRet } from './utils.ts';

/** Factory producing a fresh hash instance for one algorithm slot. */
export type MultiHashFactory = () => Hash<any>;
/** Name + factory pair used to configure {@link MultiHasher}. */
export type MultiHashEntry = readonly [name: string, factory: MultiHashFactory];
/** Async source of byte chunks accepted by {@link updateFromAsyncIterable}. */
export type AsyncBytesSource = AsyncIterable<Uint8Array> | AsyncIterator<Uint8Array>;
/** Options for {@link updateFromAsyncIterable}. */
export type AsyncHashOptions = {
  /** Optional AbortSignal; aborting cancels the read and destroys all internal state. */
  signal?: AbortSignal;
};

/**
 * Combines several independent hash algorithms into one incremental sink.
 * Every `update()` chunk is forwarded to all registered algorithms; `digest()`
 * returns a name-keyed map of independent digest copies.
 *
 * - Algorithm names keep insertion order and must be unique.
 * - If any algorithm fails to initialize, already-created instances are destroyed
 *   and no half-usable `MultiHasher` is left behind.
 * - `update()` after `digest()` is rejected, mirroring single-hash semantics.
 * - `clone()` produces fully independent state: clones never share buffers.
 * - `destroy()` wipes every internal hash and is idempotent.
 * @example
 * Hash one stream with SHA-256 and SHA-512 at the same time.
 * ```ts
 * import { sha256, sha512 } from '@noble/hashes/sha2.js';
 * import { MultiHasher } from '@noble/hashes/multihash.js';
 * const multi = new MultiHasher([
 *   ['sha256', () => sha256.create()],
 *   ['sha512', () => sha512.create()],
 * ]);
 * multi.update(new Uint8Array([97])).update(new Uint8Array([98, 99]));
 * const digests = multi.digest(); // Map { 'sha256' => ..., 'sha512' => ... }
 * multi.destroy();
 * ```
 */
export class MultiHasher {
  private readonly states: Map<string, Hash<any>> = new Map();
  private finished = false;
  private destroyed = false;
  private cached: Map<string, Uint8Array> | undefined = undefined;

  /**
   * Creates a multi-hash from name + factory pairs.
   * @param entries - iterable of `[name, factory]` pairs; factories run in order
   * @throws On wrong argument types. {@link TypeError}
   * @throws On duplicate or empty algorithm names. {@link Error}
   * @throws If a factory throws: previously created instances are destroyed first.
   */
  constructor(entries: Iterable<MultiHashEntry>) {
    if (
      entries === null ||
      entries === undefined ||
      typeof (entries as any)[Symbol.iterator] !== 'function'
    )
      throw new TypeError('expected iterable of [name, factory] entries');
    const created: Hash<any>[] = [];
    try {
      for (const entry of entries) {
        if (entry === null || entry === undefined || typeof (entry as any).length !== 'number')
          throw new TypeError('expected [name, factory] entry');
        const [name, factory] = entry;
        if (typeof name !== 'string' || name.length === 0)
          throw new TypeError('hash name must be a non-empty string');
        if (this.states.has(name)) throw new Error('duplicate hash name "' + name + '"');
        if (typeof factory !== 'function')
          throw new TypeError('factory for "' + name + '" must be a function');
        const instance = factory();
        if (
          instance === null ||
          typeof instance !== 'object' ||
          typeof instance.update !== 'function'
        )
          throw new TypeError('factory for "' + name + '" did not return a hash instance');
        created.push(instance);
        this.states.set(name, instance);
      }
      if (this.states.size === 0) throw new Error('MultiHasher needs at least one algorithm');
    } catch (err) {
      // No half-usable instance: wipe everything created so far, then rethrow.
      for (const hash of created) {
        try {
          hash.destroy();
        } catch {}
      }
      this.states.clear();
      this.destroyed = true;
      throw err;
    }
  }

  /** Algorithm names in insertion order. Returns a fresh array on every call. */
  get names(): string[] {
    return Array.from(this.states.keys());
  }

  /** Whether `digest()` was already called. */
  get isFinished(): boolean {
    return this.finished;
  }

  /** Whether `destroy()` was called. */
  get isDestroyed(): boolean {
    return this.destroyed;
  }

  private assertUsable(): void {
    if (this.destroyed) throw new Error('multihash was destroyed');
    if (this.finished) throw new Error('digest() was already called');
  }

  /**
   * Absorbs a chunk into every registered algorithm.
   * @param buf - message chunk to absorb
   * @returns The same instance for chaining.
   * @throws On wrong argument types. {@link TypeError}
   * @throws If the instance was destroyed or already finalized. {@link Error}
   */
  update(buf: TArg<Uint8Array>): this {
    abytes(buf);
    this.assertUsable();
    for (const hash of this.states.values()) hash.update(buf);
    return this;
  }

  /**
   * Finalizes all algorithms and returns independent digest copies keyed by name.
   * Repeat calls return fresh copies of the cached digests; inner state is untouched.
   * @returns Map of algorithm name to digest bytes, in insertion order.
   * @throws If the instance was destroyed. {@link Error}
   */
  digest(): Map<string, TRet<Uint8Array>> {
    if (this.destroyed) throw new Error('multihash was destroyed');
    if (!this.finished) {
      const cached = new Map<string, Uint8Array>();
      for (const [name, hash] of this.states) cached.set(name, hash.digest());
      this.cached = cached;
      this.finished = true;
    }
    const out = new Map<string, TRet<Uint8Array>>();
    for (const [name, bytes] of this.cached!) out.set(name, bytes.slice() as TRet<Uint8Array>);
    return out;
  }

  /**
   * Creates an independent copy of the current state.
   * The clone shares no buffers with the original; both can be updated
   * with different suffixes and digested separately.
   * @returns Cloned multi-hash instance.
   * @throws If the instance was destroyed or already finalized. {@link Error}
   */
  clone(): MultiHasher {
    this.assertUsable();
    const states = new Map<string, Hash<any>>();
    const created: Hash<any>[] = [];
    try {
      for (const [name, hash] of this.states) {
        const copy = hash.clone();
        created.push(copy);
        states.set(name, copy);
      }
    } catch (err) {
      for (const hash of created) {
        try {
          hash.destroy();
        } catch {}
      }
      throw err;
    }
    const multi = Object.create(MultiHasher.prototype) as MultiHasher;
    (multi as any).states = states;
    return multi;
  }

  /**
   * Wipes every internal hash instance. Idempotent: extra calls are no-ops,
   * so each inner hash is destroyed exactly once.
   */
  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    this.finished = true;
    let firstError: unknown;
    for (const hash of this.states.values()) {
      try {
        hash.destroy();
      } catch (err) {
        if (firstError === undefined) firstError = err;
      }
    }
    this.states.clear();
    this.cached = undefined;
    if (firstError !== undefined) throw firstError;
  }
}

const toAsyncIterator = (source: AsyncBytesSource): AsyncIterator<Uint8Array> => {
  if (source === null || source === undefined || typeof source !== 'object')
    throw new TypeError('expected async iterable or async iterator of Uint8Array');
  const iterable = source as AsyncIterable<Uint8Array>;
  if (typeof iterable[Symbol.asyncIterator] === 'function') return iterable[Symbol.asyncIterator]();
  const iterator = source as AsyncIterator<Uint8Array>;
  if (typeof iterator.next === 'function') return iterator;
  throw new TypeError('expected async iterable or async iterator of Uint8Array');
};

/**
 * Feeds every chunk of an async byte source into a {@link MultiHasher}.
 * On success the multi-hash stays usable and the caller owns it.
 * On cancellation (AbortSignal), read errors, or invalid chunks the iterator
 * is closed via `return()` and all internal hash state is destroyed exactly once.
 * @param multi - target multi-hash (must not be destroyed or finalized)
 * @param source - async iterable or async iterator yielding Uint8Array chunks
 * @param opts - optional AbortSignal for cancellation
 * @returns The same multi-hash instance, ready for `digest()`.
 * @throws On wrong argument types or invalid (non-Uint8Array) chunks. {@link TypeError}
 * @throws On source read errors or abort; internal state is destroyed first.
 * @example
 * Hash a stream of chunks with cleanup on failure.
 * ```ts
 * import { sha256 } from '@noble/hashes/sha2.js';
 * import { MultiHasher, updateFromAsyncIterable } from '@noble/hashes/multihash.js';
 * const multi = new MultiHasher([['sha256', () => sha256.create()]]);
 * await updateFromAsyncIterable(multi, streamOfChunks);
 * const digest = multi.digest().get('sha256');
 * ```
 */
export async function updateFromAsyncIterable(
  multi: MultiHasher,
  source: AsyncBytesSource,
  opts: AsyncHashOptions = {}
): Promise<MultiHasher> {
  if (!(multi instanceof MultiHasher)) throw new TypeError('expected MultiHasher instance');
  const { signal } = opts;
  if (signal !== undefined && typeof signal.aborted !== 'boolean')
    throw new TypeError('"signal" expected AbortSignal');
  const iterator = toAsyncIterator(source);
  const abort = (): never => {
    const reason = signal?.reason;
    throw reason instanceof Error ? reason : new Error('updateFromAsyncIterable was aborted');
  };
  try {
    for (;;) {
      if (signal?.aborted) abort();
      const { done, value } = await iterator.next();
      if (done) return multi;
      abytes(value, undefined, 'chunk');
      multi.update(value);
    }
  } catch (err) {
    // Cancel / read error / invalid chunk: close the iterator, then wipe all state.
    if (typeof iterator.return === 'function') {
      try {
        await iterator.return();
      } catch {}
    }
    try {
      multi.destroy();
    } catch {}
    throw err;
  }
}
