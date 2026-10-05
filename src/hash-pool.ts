/**
 * Rental pool for cloneable {@link Hash} instances.
 *
 * Hash objects such as `sha256.create()` hold mutable running state. Reusing one raw instance
 * across tenants would leak the previous message into the next digest. `HashPool` leases
 * instances out for exclusive use and, on return, throws the used instance away: it calls
 * `destroy()` exactly once on it and creates a fresh empty instance for the next tenant, so no
 * byte of the previous message ever survives a rental cycle.
 *
 * @module
 * @example
 * ```js
 * import { sha256 } from '@noble/hashes/sha2.js';
 * import { HashPool } from '@noble/hashes/hash-pool.js';
 *
 * const pool = new HashPool(sha256.create, { capacity: 4 });
 * const lease = await pool.acquire();
 * lease.hash.update(new TextEncoder().encode('abc'));
 * const digest = lease.hash.digest();
 * lease.release(); // destroys the used instance; next tenant gets an empty one
 * await pool.close();
 * ```
 */
import type { Hash } from './utils.ts';

/** Factory returning a fresh, empty hash instance, optionally parameterized by `opts`. */
export type PoolHashFactory<H extends Hash<H>, Opts> = (opts?: Opts) => H;

/** Options for {@link HashPool}. */
export interface HashPoolOptions<Opts> {
  /**
   * Maximum number of simultaneously leased instances. The pool never holds more instances than
   * this; `acquire()` waits once the capacity is exhausted. Must be a positive integer.
   */
  capacity: number;
  /** Options forwarded to the hash factory of every created instance. */
  opts?: Opts;
}

/** Exclusive rental of one pool-owned hash instance. */
export interface HashLease<H extends Hash<H>> {
  /** Hash instance owned exclusively by this lease until {@link HashLease.release} is called. */
  readonly hash: H;
  /**
   * Returns the instance to the pool, destroying its state exactly once and replacing it with a
   * fresh empty one (or just destroying it when the pool is closing). A duplicate call throws.
   */
  release(): void;
}

/** Rejection used for pool lifecycle violations (closed pool, woken waiters). */
export class PoolClosedError extends Error {
  constructor(message: string = 'hash pool is closed') {
    super(message);
    this.name = 'PoolClosedError';
  }
}

/**
 * Fixed-capacity rental pool for {@link Hash} instances.
 *
 * Lifecycle of an instance:
 * - created lazily by the factory on demand (at most `capacity` concurrent instances);
 * - handed out exclusively by {@link HashPool.acquire};
 * - after {@link HashLease.release}, `destroy()` is invoked exactly once on it and a brand-new
 *   empty instance takes its slot (the returned reference is dead and must not be reused);
 * - on {@link HashPool.close}, idle instances are destroyed and leases already in flight stay
 *   usable: closing waits for them to be released (each returned instance is destroyed without a
 *   replacement), wakes every waiting `acquire()` with a {@link PoolClosedError}, and afterwards
 *   refuses to lend anything.
 */
export class HashPool<H extends Hash<H>, Opts = unknown> {
  private readonly factory: PoolHashFactory<H, Opts>;
  private readonly opts: Opts | undefined;
  private readonly capacity: number;
  // Idle, empty instances ready to be leased. Never shares an instance between tenants.
  private readonly idle: H[] = [];
  // Instances currently owned by a live lease. Membership is the lease ownership certificate.
  private readonly leased = new Set<H>();
  // FIFO queue of tenants blocked in acquire(), each with its own cancellation cleanup.
  private readonly waiters: PoolWaiter<H>[] = [];
  // Resolvers of close() promises waiting for in-flight leases to come back.
  private readonly onClose: Array<() => void> = [];
  private closed = false;

  /**
   * @param factory - zero-argument (or opts-argument) constructor of fresh empty hashes,
   *   e.g. `sha256.create`
   * @param options - capacity and optional factory options
   */
  constructor(factory: PoolHashFactory<H, Opts>, options: HashPoolOptions<Opts>) {
    if (typeof factory !== 'function') throw new TypeError('hash pool factory must be a function');
    const { capacity, opts } = options;
    if (typeof capacity !== 'number' || !Number.isSafeInteger(capacity) || capacity <= 0)
      throw new TypeError('hash pool capacity must be a positive integer');
    this.factory = factory;
    this.opts = opts;
    this.capacity = capacity;
  }

  /** Current number of pool-owned instances (idle plus leased), never above capacity. */
  get size(): number {
    return this.idle.length + this.leased.size;
  }

  /** Whether {@link HashPool.close} has been invoked. */
  get isClosed(): boolean {
    return this.closed;
  }

  /** Number of tenants currently blocked in {@link HashPool.acquire}. */
  get pending(): number {
    return this.waiters.length;
  }

  /**
   * Leases one hash instance for exclusive use.
   *
   * Resolves immediately when an idle instance or an unused capacity slot exists; otherwise waits
   * in FIFO order until another tenant releases. The wait is cancellable through `signal`: an
   * aborted wait consumes no permit and leaves capacity to whoever is next in queue.
   * @param signal - optional {@link AbortSignal} that cancels the wait when aborted
   * @returns A {@link HashLease} owning the hash until its `release()`
   * @throws Rejects with the abort reason (or an `AbortError`) when cancelled while waiting, and
   *   with {@link PoolClosedError} once the pool is closed.
   */
  acquire(signal?: AbortSignal): Promise<HashLease<H>> {
    if (signal?.aborted) return Promise.reject(abortReason(signal));
    if (this.closed) return Promise.reject(new PoolClosedError());
    const hash = this.takeIdleOrCreate();
    if (hash) return Promise.resolve(this.makeLease(hash));
    return new Promise<HashLease<H>>((resolve, reject) => {
      const waiter: PoolWaiter<H> = {
        resolve: (h: H) => resolve(this.makeLease(h)),
        reject,
        cleanup: undefined,
        settled: false,
      };
      if (signal) {
        const onAbort = () => {
          if (waiter.settled) return;
          waiter.settled = true;
          this.removeWaiter(waiter);
          waiter.cleanup?.();
          reject(abortReason(signal));
        };
        signal.addEventListener('abort', onAbort, { once: true });
        waiter.cleanup = () => signal.removeEventListener('abort', onAbort);
      }
      this.waiters.push(waiter);
    });
  }

  /**
   * Closes the pool.
   *
   * Destroys every idle instance, wakes all waiting {@link HashPool.acquire} calls with
   * {@link PoolClosedError}, and stops lending. Leases still in flight are not revoked: the
   * returned promise resolves once the last one is released (each returned instance is destroyed
   * without replacement, so in-flight returns during shutdown are processed safely). Concurrent
   * and repeated calls share one resolution.
   * @returns A promise that settles when no lease remains in flight.
   */
  close(): Promise<void> {
    if (!this.closed) {
      this.closed = true;
      // Reject everyone waiting for a permit; cancellation must not recycle a permit back.
      for (const waiter of this.waiters.splice(0)) {
        waiter.settled = true;
        waiter.cleanup?.();
        waiter.reject(new PoolClosedError());
      }
      for (const hash of this.idle.splice(0)) hash.destroy();
    }
    if (this.leased.size === 0) return Promise.resolve();
    return new Promise<void>((resolve) => this.onClose.push(resolve));
  }

  private takeIdleOrCreate(): H | undefined {
    const idle = this.idle.pop();
    if (idle) return idle;
    if (this.leased.size < this.capacity) return this.factory(this.opts);
    return undefined;
  }

  private makeLease(hash: H): HashLease<H> {
    this.leased.add(hash);
    return new PoolLease<H>(hash, (h: H) => this.giveBack(h));
  }

  private removeWaiter(waiter: PoolWaiter<H>): void {
    const index = this.waiters.indexOf(waiter);
    if (index >= 0) this.waiters.splice(index, 1);
  }

  private giveBack(hash: H): void {
    // Duplicate returns and returns of instances never lent by this pool are rejected outright.
    if (!this.leased.has(hash))
      throw new Error('hash lease was already released or does not belong to this pool');
    if (this.closed) {
      // Shutdown in progress (or done): destroy without a replacement; wake close() when drained.
      this.leased.delete(hash);
      hash.destroy();
      if (this.leased.size === 0) for (const done of this.onClose.splice(0)) done();
      return;
    }
    // Build the replacement before committing the return: a factory failure keeps the old lease
    // valid so the caller can retry, and the pool never silently drops a capacity slot.
    const replacement = this.factory(this.opts);
    this.leased.delete(hash);
    // The used instance is destroyed exactly once and never handed to another tenant.
    hash.destroy();
    const waiter = this.waiters.shift();
    if (waiter) {
      waiter.settled = true;
      waiter.cleanup?.();
      waiter.resolve(replacement); // makeLease() marks the replacement leased
    } else {
      this.idle.push(replacement);
    }
  }
}

interface PoolWaiter<H extends Hash<H>> {
  resolve: (hash: H) => void;
  reject: (error: Error) => void;
  cleanup?: () => void;
  settled: boolean;
}

class PoolLease<H extends Hash<H>> implements HashLease<H> {
  readonly hash: H;
  private released = false;
  private readonly give: (hash: H) => void;
  constructor(hash: H, give: (hash: H) => void) {
    this.hash = hash;
    this.give = give;
  }
  release(): void {
    if (this.released) throw new Error('hash lease release() called twice');
    this.released = true;
    try {
      this.give(this.hash);
    } catch (error) {
      // The pool refused the return (e.g. factory failure); ownership is unchanged, allow retry.
      this.released = false;
      throw error;
    }
  }
}

function abortReason(signal: AbortSignal): Error {
  const reason = (signal as { reason?: unknown }).reason;
  if (reason instanceof Error) return reason;
  // Node/DOM may surface a non-Error reason (e.g. DOMException); propagate it verbatim.
  if (reason !== undefined) return reason as Error;
  const error = new Error('The operation was aborted');
  error.name = 'AbortError';
  return error;
}
