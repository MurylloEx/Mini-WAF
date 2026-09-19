/**
 * Tiny in-house LRU (Map insertion order + eviction).
 * No external deps. Values are treated as immutable by callers.
 */

export interface LruEntry<V> {
  readonly value: V;
  readonly expiresAt: number;
}

export class LruCache<V> {
  private readonly store = new Map<string, LruEntry<V>>();

  constructor(
    private readonly maxEntries: number,
    private readonly ttlMs = 0,
  ) {}

  get size(): number {
    return this.store.size;
  }

  has(key: string, now = Date.now()): boolean {
    return this.get(key, now) !== undefined;
  }

  get(key: string, now = Date.now()): V | undefined {
    const entry = this.store.get(key);
    if (entry === undefined) {
      return undefined;
    }
    if (this.ttlMs > 0 && now > entry.expiresAt) {
      this.store.delete(key);
      return undefined;
    }
    // Refresh recency: re-insert at the end of Map iteration order.
    this.store.delete(key);
    this.store.set(key, entry);
    return entry.value;
  }

  set(key: string, value: V, now = Date.now()): void {
    if (this.maxEntries <= 0) {
      return;
    }
    if (this.store.has(key)) {
      this.store.delete(key);
    }
    const expiresAt =
      this.ttlMs > 0 ? now + this.ttlMs : Number.POSITIVE_INFINITY;
    this.store.set(key, { value, expiresAt });
    this.evictOverflow();
  }

  clear(): void {
    this.store.clear();
  }

  private evictOverflow(): void {
    if (this.store.size <= this.maxEntries) {
      return;
    }
    const oldest = this.store.keys().next().value;
    if (oldest !== undefined) {
      this.store.delete(oldest);
    }
    this.evictOverflow();
  }
}
