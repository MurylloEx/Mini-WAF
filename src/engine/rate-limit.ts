/**
 * Sliding-window rate limiter.
 *
 * Pure helpers (`applyRateLimitHit`, `pruneRateLimitState`) stay immutable for
 * tests and callers that want value semantics.
 *
 * {@link RateLimitStore} mutates in place on the hot path: per-key updates only
 * (no full-Map clone), LRU eviction under a key cap, and opportunistic idle prune.
 */

export interface RateLimitHit {
  readonly count: number;
  readonly remaining: number;
  readonly exceeded: boolean;
  readonly resetAt: number;
}

/** key → timestamps inside the current window (newest last). */
export type RateLimitState = ReadonlyMap<string, readonly number[]>;

/** A fresh, empty rate-limit state. */
export function emptyRateLimitState(): RateLimitState {
  return new Map<string, readonly number[]>();
}

export interface RateLimitTransition {
  readonly state: RateLimitState;
  readonly hit: RateLimitHit;
}

/** Minimal port used by the evaluator (store or test double). */
export interface RateLimitPort {
  hit(
    key: string,
    max: number,
    windowMs: number,
    now?: number,
  ): RateLimitHit;
}

export interface RateLimitStoreOptions {
  /**
   * Maximum distinct keys retained. Cold keys are evicted (LRU) when exceeded.
   * Default: {@link DEFAULT_MAX_RATE_LIMIT_KEYS}.
   */
  readonly maxKeys?: number;
  /**
   * Drop keys whose newest timestamp is older than this many ms.
   * Default: {@link DEFAULT_RATE_LIMIT_IDLE_MS}.
   */
  readonly idleMs?: number;
  /**
   * Run a full idle prune every N `hit` calls. `0` disables opportunistic prune
   * (explicit {@link RateLimitStore.prune} / overflow eviction still apply).
   * Default: {@link DEFAULT_RATE_LIMIT_PRUNE_EVERY}.
   */
  readonly pruneEveryHits?: number;
}

/** Default cap on distinct rate-limit keys (DoS / memory bound). */
export const DEFAULT_MAX_RATE_LIMIT_KEYS = 10_000;
/** Default idle TTL before a key is eligible for opportunistic prune. */
export const DEFAULT_RATE_LIMIT_IDLE_MS = 120_000;
/** Default hit interval between opportunistic full prunes. */
export const DEFAULT_RATE_LIMIT_PRUNE_EVERY = 1_024;

function buildHit(
  timestamps: readonly number[],
  max: number,
  windowMs: number,
  now: number,
): RateLimitHit {
  const count = timestamps.length;
  const oldest = timestamps[0] ?? now;
  return {
    count,
    remaining: Math.max(0, max - count),
    exceeded: count > max,
    resetAt: oldest + windowMs,
  };
}

function timestampsAfterHit(
  previous: readonly number[],
  windowMs: number,
  now: number,
): readonly number[] {
  const cutoff = now - windowMs;
  return [...previous.filter((ts) => ts > cutoff), now];
}

/**
 * Pure transition: previous state + key → next state + hit info.
 * Clones the map (fine for tests / ephemeral use; hot path uses the store).
 */
export function applyRateLimitHit(
  state: RateLimitState,
  key: string,
  max: number,
  windowMs: number,
  now = Date.now(),
): RateLimitTransition {
  const timestamps = timestampsAfterHit(state.get(key) ?? [], windowMs, now);
  const next = new Map(state);
  next.set(key, timestamps);
  return {
    state: next,
    hit: buildHit(timestamps, max, windowMs, now),
  };
}

/**
 * Pure prune: drop buckets whose last timestamp is older than `olderThanMs`.
 */
export function pruneRateLimitState(
  state: RateLimitState,
  olderThanMs: number,
  now = Date.now(),
): RateLimitState {
  const next = new Map<string, readonly number[]>();
  for (const [key, timestamps] of state) {
    const last = timestamps[timestamps.length - 1];
    if (last !== undefined && now - last <= olderThanMs) {
      next.set(key, timestamps);
    }
  }
  return next;
}

/**
 * Shared mutable store: atomic per-key hits, LRU key cap, idle prune.
 * Safe under concurrent `handle` + event-loop yields (Node single-thread:
 * each `hit` completes before the next can interleave).
 */
export class RateLimitStore implements RateLimitPort {
  private readonly buckets = new Map<string, number[]>();
  private readonly maxKeys: number;
  private readonly idleMs: number;
  private readonly pruneEveryHits: number;
  private hitsSincePrune = 0;

  constructor(
    initial: RateLimitState = emptyRateLimitState(),
    options: RateLimitStoreOptions = {},
  ) {
    this.maxKeys = options.maxKeys ?? DEFAULT_MAX_RATE_LIMIT_KEYS;
    this.idleMs = options.idleMs ?? DEFAULT_RATE_LIMIT_IDLE_MS;
    this.pruneEveryHits =
      options.pruneEveryHits ?? DEFAULT_RATE_LIMIT_PRUNE_EVERY;

    for (const [key, timestamps] of initial) {
      this.buckets.set(key, [...timestamps]);
    }
    this.evictOverflow();
  }

  /**
   * Readonly snapshot (copies buckets). For inspection / tests — not on the
   * request hot path.
   */
  snapshot(): RateLimitState {
    const copy = new Map<string, readonly number[]>();
    for (const [key, timestamps] of this.buckets) {
      copy.set(key, [...timestamps]);
    }
    return copy;
  }

  /**
   * Record one hit for `key`. Mutates only that bucket + LRU order.
   * O(window size for key), not O(all keys).
   */
  hit(key: string, max: number, windowMs: number, now = Date.now()): RateLimitHit {
    const previous = this.buckets.get(key);
    const timestamps = [
      ...timestampsAfterHit(previous ?? [], windowMs, now),
    ];

    if (previous !== undefined) {
      this.buckets.delete(key);
    }
    this.buckets.set(key, timestamps);

    this.evictOverflow();
    this.maybeOpportunisticPrune(now);

    return buildHit(timestamps, max, windowMs, now);
  }

  prune(olderThanMs: number = this.idleMs, now = Date.now()): void {
    for (const [key, timestamps] of this.buckets) {
      const last = timestamps[timestamps.length - 1];
      if (last === undefined || now - last > olderThanMs) {
        this.buckets.delete(key);
      }
    }
    this.hitsSincePrune = 0;
  }

  /**
   * Replace all buckets from a ReadonlyMap (tests / rare admin paths).
   * Prefer {@link hit} on the request path.
   */
  replace(next: RateLimitState): void {
    this.buckets.clear();
    for (const [key, timestamps] of next) {
      this.buckets.set(key, [...timestamps]);
    }
    this.evictOverflow();
  }

  clear(): void {
    this.buckets.clear();
    this.hitsSincePrune = 0;
  }

  size(): number {
    return this.buckets.size;
  }

  private maybeOpportunisticPrune(now: number): void {
    if (this.pruneEveryHits <= 0) {
      return;
    }
    this.hitsSincePrune += 1;
    if (this.hitsSincePrune < this.pruneEveryHits) {
      return;
    }
    this.prune(this.idleMs, now);
  }

  private evictOverflow(): void {
    if (this.maxKeys <= 0) {
      this.buckets.clear();
      return;
    }
    while (this.buckets.size > this.maxKeys) {
      const oldest = this.buckets.keys().next().value;
      if (oldest === undefined) {
        return;
      }
      this.buckets.delete(oldest);
    }
  }
}
