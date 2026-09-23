/**
 * HMAC_DRBG: deterministic random bit generator from NIST SP 800-90A Rev. 1,
 * instantiated with HMAC-SHA-256 (10.1.2, 256-bit security strength).
 *
 * This module is a *mechanism only*: every seed is supplied explicitly by the
 * caller. It never touches a system randomness source, which makes it suitable
 * for reproducible protocol tests. It does NOT:
 *
 * - obtain or validate a qualified entropy source for you;
 * - provide prediction resistance (no automatic reseeding between requests);
 * - claim any form of certification/validation.
 *
 * There is deliberately no state serialization or cloning API.
 * @module
 */
import { hmac } from './hmac.ts';
import { sha256 } from './sha2.ts';
import { abytes, anumber, clean, concatBytes, copyBytes } from './utils.ts';

/** Output length of SHA-256 (and of K / V) in bytes. */
const OUT_LEN = 32;
/** Minimum entropy input length in bytes (256-bit security strength). */
export const HMAC_DRBG_MIN_ENTROPY_BYTES = 32;
/** Minimum nonce length in bytes (half of the security strength). */
export const HMAC_DRBG_MIN_NONCE_BYTES = 16;
/** Maximum number of bytes a single generate request may return (2^19 bits). */
export const HMAC_DRBG_MAX_GENERATE_BYTES = 65536;
/**
 * Reseed interval: maximum number of generate requests between reseeds (2^48).
 * A bigint is used so the boundary is represented exactly.
 */
export const HMAC_DRBG_RESEED_INTERVAL: bigint = 1n << 48n;

const EMPTY = /* @__PURE__ */ new Uint8Array(0);

function checkBytes(value: Uint8Array, minLength: number, title: string): Uint8Array {
  abytes(value, undefined, title);
  if (value.length < minLength)
    throw new RangeError(
      `HMAC_DRBG: ${title} must be at least ${minLength} bytes, got ${value.length}`
    );
  return value;
}

function optBytes(value: Uint8Array | undefined, title: string): Uint8Array {
  if (value === undefined) return EMPTY;
  abytes(value, undefined, title);
  return value;
}

/**
 * HMAC_DRBG with SHA-256 per NIST SP 800-90A Rev. 1 section 10.1.2.
 * Construct via {@link HMAC_DRBG.instantiate}.
 */
export class HMAC_DRBG {
  private K: Uint8Array;
  private V: Uint8Array;
  // Exact integer for the 2^48 reseed interval boundary.
  private counter: bigint;
  private destroyed = false;

  private constructor() {
    this.K = new Uint8Array(OUT_LEN); // 0x00 * 32
    this.V = new Uint8Array(OUT_LEN).fill(0x01); // 0x01 * 32
    this.counter = 0n;
  }

  /**
   * Instantiates a DRBG (10.1.2.3) from explicit caller-supplied material.
   * No system randomness is used. Inputs are copied: later mutation of the
   * caller's arrays does not affect the instance.
   * @param entropy - at least 32 bytes
   * @param nonce - at least 16 bytes
   * @param personalization - optional personalization string
   */
  static instantiate(
    entropy: Uint8Array,
    nonce: Uint8Array,
    personalization: Uint8Array = EMPTY
  ): HMAC_DRBG {
    const ent = copyBytes(checkBytes(entropy, HMAC_DRBG_MIN_ENTROPY_BYTES, 'entropy'));
    const non = copyBytes(checkBytes(nonce, HMAC_DRBG_MIN_NONCE_BYTES, 'nonce'));
    const per = copyBytes(optBytes(personalization, 'personalization'));
    const drbg = new HMAC_DRBG();
    drbg.update(concatBytes(ent, non, per));
    drbg.counter = 1n;
    clean(ent, non, per);
    return drbg;
  }

  /** Current reseed counter value (number of requests since last reseed, plus one). */
  get reseedCounter(): bigint {
    return this.counter;
  }

  private assertActive(): void {
    if (this.destroyed) throw new Error('HMAC_DRBG: instance is destroyed');
  }

  // HMAC_DRBG_Update (10.1.2.2). Handles empty provided_data correctly:
  // with empty data only the first pair of HMAC invocations runs.
  private update(providedData: Uint8Array): void {
    this.K = hmac(sha256, this.K, concatBytes(this.V, new Uint8Array([0x00]), providedData));
    this.V = hmac(sha256, this.K, this.V);
    if (providedData.length !== 0) {
      this.K = hmac(sha256, this.K, concatBytes(this.V, new Uint8Array([0x01]), providedData));
      this.V = hmac(sha256, this.K, this.V);
    }
  }

  /**
   * Reseeds the DRBG (10.1.2.4) from explicit caller-supplied entropy.
   * @param entropy - at least 32 bytes
   * @param additionalInput - optional additional input
   */
  reseed(entropy: Uint8Array, additionalInput: Uint8Array = EMPTY): void {
    this.assertActive();
    const ent = copyBytes(checkBytes(entropy, HMAC_DRBG_MIN_ENTROPY_BYTES, 'entropy'));
    const add = copyBytes(optBytes(additionalInput, 'additionalInput'));
    this.update(concatBytes(ent, add));
    this.counter = 1n;
    clean(ent, add);
  }

  /**
   * Generates pseudorandom bytes (10.1.2.5). All validation happens before
   * any state change: on error the instance is left untouched and no partial
   * output is produced. The returned array is freshly allocated and never
   * aliases the internal K / V state.
   * @param nbytes - requested output length, 1..65536 bytes
   * @param additionalInput - optional additional input
   */
  generate(nbytes: number, additionalInput: Uint8Array = EMPTY): Uint8Array {
    this.assertActive();
    anumber(nbytes, 'nbytes');
    if (!Number.isInteger(nbytes) || nbytes < 1 || nbytes > HMAC_DRBG_MAX_GENERATE_BYTES)
      throw new RangeError(
        `HMAC_DRBG: nbytes must be an integer in 1..${HMAC_DRBG_MAX_GENERATE_BYTES}, got ${nbytes}`
      );
    if (this.counter > HMAC_DRBG_RESEED_INTERVAL)
      throw new Error('HMAC_DRBG: reseed interval (2^48 requests) exhausted, reseed required');
    const add = copyBytes(optBytes(additionalInput, 'additionalInput'));
    if (add.length !== 0) this.update(add);
    const out = new Uint8Array(nbytes);
    for (let pos = 0; pos < nbytes; pos += OUT_LEN) {
      this.V = hmac(sha256, this.K, this.V);
      out.set(this.V.subarray(0, Math.min(OUT_LEN, nbytes - pos)), pos);
    }
    this.update(add);
    clean(add);
    this.counter += 1n;
    return out;
  }

  /**
   * Zeroizes the internal state. After destroy, every operation on the
   * instance fails; there is no way to recover the previous state.
   */
  destroy(): void {
    clean(this.K, this.V);
    this.counter = 0n;
    this.destroyed = true;
  }
}
