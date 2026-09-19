import { describe, expect, it } from 'vitest';
import {
  applyRateLimitHit,
  emptyRateLimitState,
  pruneRateLimitState,
  RateLimitStore,
} from '@/engine/rate-limit';

describe('applyRateLimitHit (immutable)', () => {
  it('returns a new map and does not mutate the previous state', () => {
    const initial = emptyRateLimitState();
    const first = applyRateLimitHit(initial, 'ip:1', 2, 60_000, 1_000);
    expect(initial.size).toBe(0);
    expect(first.state.size).toBe(1);
    expect(first.hit.exceeded).toBe(false);
    expect(first.hit.count).toBe(1);

    const second = applyRateLimitHit(first.state, 'ip:1', 2, 60_000, 1_100);
    expect(first.state.get('ip:1')).toEqual([1_000]);
    expect(second.hit.count).toBe(2);
    expect(second.hit.exceeded).toBe(false);

    const third = applyRateLimitHit(second.state, 'ip:1', 2, 60_000, 1_200);
    expect(third.hit.exceeded).toBe(true);
    expect(third.hit.count).toBe(3);
  });

  it('prunes idle buckets into a new map', () => {
    let state = emptyRateLimitState();
    state = applyRateLimitHit(state, 'a', 10, 1_000, 0).state;
    state = applyRateLimitHit(state, 'b', 10, 1_000, 5_000).state;
    const pruned = pruneRateLimitState(state, 2_000, 5_500);
    expect(pruned.has('a')).toBe(false);
    expect(pruned.has('b')).toBe(true);
  });
});

describe('RateLimitStore', () => {
  it('replaces state atomically via replace()', () => {
    const store = new RateLimitStore();
    const hit = store.hit('k', 1, 1000, 10);
    expect(hit.count).toBe(1);

    const snapshot = store.snapshot();
    const next = applyRateLimitHit(snapshot, 'k', 1, 1000, 20).state;
    store.replace(next);
    expect(store.snapshot()).toBe(next);
    expect(store.snapshot()).not.toBe(snapshot);
  });
});
