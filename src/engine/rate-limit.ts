/**
 * Immutable sliding-window rate limiter.
 *
 * State is a ReadonlyMap; every hit returns a new map (never mutates in place).
 */

export interface RateLimitHit {
  readonly count: number;
  readonly remaining: number;
  readonly exceeded: boolean;
  readonly resetAt: number;
}

/** key → timestamps inside the current window (newest last). */
export type RateLimitState = ReadonlyMap<string, readonly number[]>;

export function emptyRateLimitState(): RateLimitState {
  return new Map<string, readonly number[]>();
}

export interface RateLimitTransition {
  readonly state: RateLimitState;
  readonly hit: RateLimitHit;
}

/**
 * Pure transition: previous state + key → next state + hit info.
 */
export function applyRateLimitHit(
  state: RateLimitState,
  key: string,
  max: number,
  windowMs: number,
  now = Date.now(),
): RateLimitTransition {
  const previous = state.get(key) ?? [];
  const cutoff = now - windowMs;
  const timestamps: readonly number[] = [
    ...previous.filter((ts) => ts > cutoff),
    now,
  ];

  const next = new Map(state);
  next.set(key, timestamps);

  const count = timestamps.length;
  const oldest = timestamps[0] ?? now;

  return {
    state: next,
    hit: {
      count,
      remaining: Math.max(0, max - count),
      exceeded: count > max,
      resetAt: oldest + windowMs,
    },
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
 * Thin store that replaces its ReadonlyMap on each update.
 * Encapsulates the single mutable reference; never mutates map contents.
 */
export class RateLimitStore {
  private state: RateLimitState;

  constructor(initial: RateLimitState = emptyRateLimitState()) {
    this.state = initial;
  }

  snapshot(): RateLimitState {
    return this.state;
  }

  hit(key: string, max: number, windowMs: number, now = Date.now()): RateLimitHit {
    const transition = applyRateLimitHit(this.state, key, max, windowMs, now);
    this.state = transition.state;
    return transition.hit;
  }

  prune(olderThanMs: number, now = Date.now()): void {
    this.state = pruneRateLimitState(this.state, olderThanMs, now);
  }

  /** Atomically replace the whole ReadonlyMap (used after pure scan). */
  replace(next: RateLimitState): void {
    this.state = next;
  }

  clear(): void {
    this.state = emptyRateLimitState();
  }

  size(): number {
    return this.state.size;
  }
}
