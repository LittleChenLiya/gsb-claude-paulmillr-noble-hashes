/**
 * Multi-hash: feed the same bytes into several hash algorithms in a single pass.
 *
 * {@link MultiHasher} fans every `update()` chunk out to caller-specified hash instances,
 * while {@link hashStream} adapts an (async) byte iterator into a multi-hash with
 * guaranteed cleanup on cancellation or read errors.
 * @module
 */
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { abytes, aexists, copyBytes, type Hash, type TArg, type TRet } from './utils.ts';

/**
 * Named hash factory consumed by {@link MultiHasher}.
 * Names are unique per multi-hasher and keep insertion order.
 */
export type MultiHashSpec = {
  /** Unique algorithm label used as key in {@link MultiHashDigests}. */
  name: string;
  /** Factory returning a fresh hash instance. Called once per MultiHasher construction. */
  create: () => Hash<any>;
};

/**
 * Named digest map returned by {@link MultiHasher.digest} and {@link hashStream}.
 * Keys follow spec insertion order; values are freshly allocated copies.
 */
export type MultiHashDigests = Readonly<Record<string, TRet<Uint8Array>>>;

/** Options for {@link hashStream}. */
export type HashStreamOptions = {
  /** Optional abort signal: aborting closes the source iterator and destroys the hasher. */
  signal?: AbortSignal;
};

const ahashInstance = (name: string, instance: any): void => {
  if (
    instance === null ||
    typeof instance !== 'object' ||
    typeof instance.update !== 'function' ||
    typeof instance.digest !== 'function' ||
    typeof instance.clone !== 'function' ||
    typeof instance.destroy !== 'function'
  )
    throw new TypeError('"' + name + '" factory did not return a hash instance');
};

/**
 * Runs several hash algorithms over the same message in a single pass.
 *
 * - Spec names keep insertion order and must be unique.
 * - If any factory throws during construction, already-created instances are destroyed,
 *   so a failed construction never leaves a half-usable instance behind.
 * - `update()` after `digest()` is rejected, like every other noble hash.
 * - `clone()` deep-clones every inner hash; clones share no state.
 * - `destroy()` is idempotent and destroys every inner hash exactly once.
 * @example
 * Hash one message with SHA-256 and SHA-512 at the same time.
 * ```ts
 * import { MultiHasher } from '@noble/hashes/multihash.js';
 * import { sha256, sha512 } from '@noble/hashes/sha2.js';
 * const mh = new MultiHasher([
 *   { name: 'sha256', create: () => sha256.create() },
 *   { name: 'sha512', create: () => sha512.create() },
 * ]);
 * mh.update(new Uint8Array([0x61])).update(new Uint8Array([0x62, 0x63]));
 * const { sha256: a, sha512: b } = mh.digest();
 * ```
 */
export class MultiHasher {
  private entries: [string, Hash<any>][];
  private finished: boolean = false;
  private destroyed: boolean = false;

  /**
   * Builds a multi-hasher from named hash factories.
   * @param specs - iterable of `{ name, create }` entries; names must be unique and non-empty
   * @throws On invalid specs, duplicate names, or factory failures (inner hashes are cleaned up).
   * {@link TypeError} {@link Error}
   */
  constructor(specs: Iterable<MultiHashSpec>) {
    if (specs === null || (typeof specs !== 'object' && typeof specs !== 'function'))
      throw new TypeError('expected iterable of {name, create} specs');
    const iterator = (specs as any)[Symbol.iterator];
    if (typeof iterator !== 'function')
      throw new TypeError('expected iterable of {name, create} specs');
    const entries: [string, Hash<any>][] = [];
    const seen = new Set<string>();
    try {
      for (const spec of specs) {
        if (spec === null || typeof spec !== 'object')
          throw new TypeError('expected {name, create} spec, got type=' + typeof spec);
        const { name, create } = spec;
        if (typeof name !== 'string' || name.length === 0)
          throw new TypeError('spec name must be a non-empty string');
        if (typeof create !== 'function')
          throw new TypeError('"' + name + '" create must be a function');
        if (seen.has(name)) throw new Error('duplicate hash name "' + name + '"');
        seen.add(name);
        const instance = create();
        ahashInstance(name, instance);
        entries.push([name, instance]);
      }
    } catch (err) {
      // Roll back: a failed construction must not leak half-initialized hash state.
      for (const [, instance] of entries) instance.destroy();
      throw err;
    }
    if (entries.length === 0) throw new Error('MultiHasher needs at least one hash');
    this.entries = entries;
  }

  /**
   * Algorithm names in spec insertion order.
   * @returns Frozen array of names; mutating it cannot affect the hasher.
   */
  get names(): readonly string[] {
    return Object.freeze(this.entries.map(([name]) => name));
  }

  /**
   * Absorbs a chunk into every inner hash.
   * @param buf - message chunk to absorb
   * @returns The same multi-hasher for chaining.
   * @throws If the hasher was destroyed or already finalized. {@link Error}
   */
  update(buf: TArg<Uint8Array>): this {
    aexists(this);
    abytes(buf);
    for (const [, instance] of this.entries) instance.update(buf);
    return this;
  }

  /**
   * Finalizes every inner hash and returns named, independently owned digests.
   * Each returned array is a fresh copy: mutating it cannot affect inner state.
   * @returns Frozen map from algorithm name to digest bytes.
   * @throws If the hasher was destroyed or already finalized. {@link Error}
   */
  digest(): MultiHashDigests {
    aexists(this);
    this.finished = true;
    const out: Record<string, TRet<Uint8Array>> = Object.create(null);
    for (const [name, instance] of this.entries) out[name] = copyBytes(instance.digest());
    return Object.freeze(out);
  }

  /**
   * Creates an independent copy: every inner hash is cloned, nothing is shared.
   * @returns Cloned multi-hasher.
   * @throws If the hasher was destroyed. {@link Error}
   */
  clone(): MultiHasher {
    aexists(this, false);
    const copy = Object.create(MultiHasher.prototype) as MultiHasher;
    copy.entries = this.entries.map(
      ([name, instance]) => [name, instance.clone()] as [string, Hash<any>]
    );
    copy.finished = this.finished;
    copy.destroyed = false;
    return copy;
  }

  /**
   * Wipes every inner hash exactly once and makes the instance unusable.
   * Calling `destroy()` repeatedly is safe and does not re-destroy inner hashes.
   * @returns Nothing.
   */
  destroy(): void {
    if (this.destroyed) return;
    this.destroyed = true;
    const entries = this.entries;
    this.entries = [];
    for (const [, instance] of entries) instance.destroy();
  }
}

/**
 * Convenience factory mirroring the noble `.create()` style.
 * @param specs - iterable of `{ name, create }` entries
 * @returns New multi-hasher.
 * @example
 * Create a multi-hasher without `new`.
 * ```ts
 * const mh = createMultiHasher([{ name: 'sha256', create: () => sha256.create() }]);
 * ```
 */
export function createMultiHasher(specs: Iterable<MultiHashSpec>): MultiHasher {
  return new MultiHasher(specs);
}

/**
 * Hashes every chunk of a byte stream with a {@link MultiHasher}.
 *
 * Cleanup guarantees:
 * - On a source read error, an invalid (non-Uint8Array) chunk, an update failure, or an
 *   abort, the source iterator is closed via `iterator.return()` and the hasher is
 *   destroyed exactly once before the error is re-thrown.
 * - An empty stream simply yields the digests of an empty message.
 * @param source - async (or sync) iterable of Uint8Array chunks
 * @param hasher - multi-hasher absorbing the chunks
 * @param opts - optional abort signal
 * @returns Named digests once the stream is exhausted.
 * @throws On invalid arguments, stream errors, invalid chunks, or abort. {@link TypeError}
 * @example
 * Hash an async byte stream.
 * ```ts
 * const digests = await hashStream(readFileChunks('f.bin'), createMultiHasher([
 *   { name: 'sha256', create: () => sha256.create() },
 * ]));
 * ```
 */
export async function hashStream(
  source: AsyncIterable<TArg<Uint8Array>> | Iterable<TArg<Uint8Array>>,
  hasher: MultiHasher,
  opts: HashStreamOptions = {}
): Promise<MultiHashDigests> {
  if (source === null || (typeof source !== 'object' && typeof source !== 'function'))
    throw new TypeError('expected iterable or async iterable of Uint8Array chunks');
  const asyncIterator = (source as any)[Symbol.asyncIterator];
  const syncIterator = (source as any)[Symbol.iterator];
  if (typeof asyncIterator !== 'function' && typeof syncIterator !== 'function')
    throw new TypeError('expected iterable or async iterable of Uint8Array chunks');
  if (!(hasher instanceof MultiHasher)) throw new TypeError('expected MultiHasher instance');
  const { signal } = opts;
  const iterator: Iterator<TArg<Uint8Array>> | AsyncIterator<TArg<Uint8Array>> =
    typeof asyncIterator === 'function' ? asyncIterator.call(source) : syncIterator.call(source);
  try {
    for (;;) {
      if (signal !== undefined && signal.aborted)
        throw signal.reason instanceof Error ? signal.reason : new Error('hashStream aborted');
      const step = await iterator.next();
      if (step.done) break;
      // abytes() rejects non-Uint8Array chunks; update() rejects destroyed/finalized hashers.
      hasher.update(abytes(step.value, undefined, 'chunk'));
    }
  } catch (err) {
    hasher.destroy();
    if (typeof iterator.return === 'function') {
      try {
        await iterator.return();
      } catch {
        // Closing the iterator is best-effort; the original error takes precedence.
      }
    }
    throw err;
  }
  return hasher.digest();
}
