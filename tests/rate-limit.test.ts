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
    const withA = applyRateLimitHit(emptyRateLimitState(), 'a', 10, 1_000, 0)
      .state;
    const withBoth = applyRateLimitHit(withA, 'b', 10, 1_000, 5_000).state;
    const pruned = pruneRateLimitState(withBoth, 2_000, 5_500);
    expect(pruned.has('a')).toBe(false);
    expect(pruned.has('b')).toBe(true);
  });
});

describe('RateLimitStore', () => {
  it('applies hits in place without losing prior keys', () => {
    const store = new RateLimitStore();
    expect(store.hit('a', 10, 1_000, 10).count).toBe(1);
    expect(store.hit('b', 10, 1_000, 20).count).toBe(1);
    expect(store.hit('a', 10, 1_000, 30).count).toBe(2);
    expect(store.size()).toBe(2);
    expect(store.snapshot().get('a')).toEqual([10, 30]);
    expect(store.snapshot().get('b')).toEqual([20]);
  });

  it('evicts the least-recently used key when over maxKeys', () => {
    const store = new RateLimitStore(emptyRateLimitState(), {
      maxKeys: 2,
      pruneEveryHits: 0,
    });
    store.hit('a', 100, 60_000, 1);
    store.hit('b', 100, 60_000, 2);
    store.hit('a', 100, 60_000, 3); // refresh a
    store.hit('c', 100, 60_000, 4); // evicts b
    expect(store.size()).toBe(2);
    expect(store.snapshot().has('a')).toBe(true);
    expect(store.snapshot().has('b')).toBe(false);
    expect(store.snapshot().has('c')).toBe(true);
  });

  it('prunes idle keys', () => {
    const store = new RateLimitStore(emptyRateLimitState(), {
      maxKeys: 100,
      pruneEveryHits: 0,
      idleMs: 1_000,
    });
    store.hit('old', 10, 500, 0);
    store.hit('fresh', 10, 500, 5_000);
    store.prune(2_000, 5_500);
    expect(store.snapshot().has('old')).toBe(false);
    expect(store.snapshot().has('fresh')).toBe(true);
  });

  it('replace() reseeds buckets from a ReadonlyMap', () => {
    const store = new RateLimitStore();
    store.hit('k', 1, 1000, 10);
    const next = applyRateLimitHit(emptyRateLimitState(), 'k', 1, 1000, 20)
      .state;
    store.replace(next);
    expect(store.snapshot().get('k')).toEqual([20]);
    expect(store.size()).toBe(1);
  });
});
