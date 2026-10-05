/**
 * Small lease pool for cloneable hash instances.
 *
 * A pool hands out hash instances for exclusive use: while a lease is held, nobody else can
 * touch the same instance. On {@link Lease.release | release} the old state is destroyed and a
 * brand-new, empty instance is created, so no message residue from the previous caller can leak
 * to the next one.
 *
 * ## Lifecycle
 *
 * 1. {@link HashPool.acquire} reserves a permit and returns a {@link Lease} wrapping a fresh,
 *    empty hash instance. If every permit is taken, the call waits in a FIFO queue; the wait can
 *    be cancelled through an `AbortSignal`, in which case no permit is consumed.
 * 2. The holder uses the hash exclusively (update / digest / clone).
 * 3. {@link Lease.release} returns the permit: the instance state is destroyed exactly once and a
 *    fresh empty instance is created. It is handed to the next waiter or kept idle for the next
 *    acquire. Releasing the same lease twice throws.
 * 4. {@link HashPool.close} stops lending: queued waiters are rejected and no new instances are
 *    created. Leases already checked out can still be released; their state is destroyed and the
 *    permit is retired instead of re-lent.
 *
 * @module
 * @example
 * ```ts
 * import { sha256 } from '@noble/hashes/sha2.js';
 * import { HashPool } from '@noble/hashes/pool.js';
 *
 * const pool = new HashPool(sha256.create, { capacity: 1 });
 *
 * const a = await pool.acquire();
 * a.hash.update(new Uint8Array([97, 98, 99]));
 * a.hash.digest(); // ba7816bf...
 * a.release();     // old state destroyed, empty instance created
 *
 * const b = await pool.acquire();
 * b.hash.digest(); // e3b0c442... (empty digest, no residue from "abc")
 * b.release();
 *
 * pool.close();
 * ```
 */
import type { Hash } from './utils.ts';

/** A checked-out hash instance with the exclusive right to use it. */
export interface Lease<T extends Hash<T>> {
  /** The hash instance for exclusive use until {@link Lease.release} is called. */
  readonly hash: T;
  /**
   * Returns the permit to the pool. Destroys the instance state and creates a fresh empty one.
   * @throws If the lease has already been released.
   */
  release(): void;
}

/** Options for {@link HashPool}. */
export interface HashPoolOptions {
  /** Maximum number of hash instances that can be leased out at the same time. Default: 1. */
  capacity?: number;
}

type Waiter<T extends Hash<T>> = {
  resolve: (lease: Lease<T>) => void;
  reject: (err: Error) => void;
  signal?: AbortSignal;
  onAbort: () => void;
};

type Destroyable = Hash<any> & { destroyed?: boolean };

/**
 * Pools cloneable hash instances so they can be borrowed exclusively and reset between callers.
 */
export class HashPool<T extends Hash<T>> {
  private readonly hashCons: () => T;
  private readonly capacity: number;
  private active = 0;
  private idle: T | null = null;
  private closed = false;
  private waiters: Waiter<T>[] = [];

  /**
   * @param hashCons - zero-argument factory that creates a fresh hash instance (e.g. `sha256.create`).
   * @param opts - pool options, see {@link HashPoolOptions}.
   */
  constructor(hashCons: () => T, opts: HashPoolOptions = {}) {
    if (typeof hashCons !== 'function')
      throw new TypeError('"hashCons" expected function, got type=' + typeof hashCons);
    const capacity = opts.capacity ?? 1;
    if (!Number.isInteger(capacity) || capacity < 1)
      throw new TypeError('"capacity" expected positive integer, got ' + opts.capacity);
    this.hashCons = hashCons;
    this.capacity = capacity;
  }

  /**
   * Reserves a permit and returns a lease for a fresh, empty hash instance.
   *
   * When the pool is at capacity, the returned promise stays pending in a FIFO queue until a
   * permit is returned. Pass an `AbortSignal` to cancel the wait; cancellation rejects the
   * promise and does not consume a permit.
   *
   * @param signal - optional signal used to cancel a pending wait.
   * @returns A promise resolving to the lease.
   * @throws If the pool is closed.
   */
  async acquire(signal?: AbortSignal): Promise<Lease<T>> {
    if (this.closed) throw new Error('pool is closed');
    if (signal?.aborted) throw signal.reason ?? new Error('acquire aborted');
    if (this.active < this.capacity) {
      this.active++;
      const hash = this.idle ?? this.hashCons();
      this.idle = null;
      return this.makeLease(hash);
    }
    return new Promise<Lease<T>>((resolve, reject) => {
      const waiter: Waiter<T> = { resolve, reject, signal, onAbort: () => {} };
      if (signal) {
        waiter.onAbort = () => {
          const idx = this.waiters.indexOf(waiter);
          if (idx !== -1) {
            this.waiters.splice(idx, 1);
            reject(signal.reason ?? new Error('acquire aborted'));
          }
        };
        signal.addEventListener('abort', waiter.onAbort, { once: true });
      }
      this.waiters.push(waiter);
    });
  }

  /**
   * Stops lending. Rejects all queued waiters. Leases already checked out can still be released;
   * their state is destroyed and the permit is retired instead of being re-lent.
   * Idle instances are destroyed. Calling this more than once is a no-op.
   */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    if (this.idle) {
      destroyHash(this.idle);
      this.idle = null;
    }
    const err = new Error('pool is closed');
    for (const w of this.waiters.splice(0)) {
      if (w.signal) w.signal.removeEventListener('abort', w.onAbort);
      w.reject(err);
    }
  }

  private makeLease(hash: T): Lease<T> {
    let released = false;
    return {
      hash,
      release: () => {
        if (released) throw new Error('lease already released');
        released = true;
        this.returnLease(hash);
      },
    };
  }

  private returnLease(hash: T): void {
    // Wipe the old state. A hash that was finalized via digest() is already destroyed, so guard
    // against a second destroy() call: destruction must happen exactly once per instance.
    destroyHash(hash);
    if (this.closed) {
      // Pool is gone: retire the permit, do not create a fresh instance or wake waiters.
      this.active--;
      return;
    }
    const fresh = this.hashCons();
    const waiter = this.waiters.shift();
    if (waiter) {
      if (waiter.signal) waiter.signal.removeEventListener('abort', waiter.onAbort);
      // The permit transfers from the returning holder to the waiter; active count stays.
      waiter.resolve(this.makeLease(fresh));
    } else {
      this.active--;
      // Keep at most one idle instance: retire the previous empty one so it is destroyed once
      // instead of being dropped on the floor.
      if (this.idle) destroyHash(this.idle);
      this.idle = fresh;
    }
  }
}

/** Destroys a hash instance exactly once. Finalized hashes already set `destroyed`, so skip them. */
function destroyHash(hash: Destroyable): void {
  if (!hash.destroyed) hash.destroy();
}
