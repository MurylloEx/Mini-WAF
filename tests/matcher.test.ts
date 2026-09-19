import { describe, expect, it } from 'vitest';
import { matchesPattern, includesIgnoreCase } from '@/engine/matcher';

describe('matchesPattern', () => {
  it('matches exact strings', () => {
    expect(matchesPattern('abc', 'abc')).toBe(true);
    expect(matchesPattern('abc', 'ab')).toBe(false);
  });

  it('matches regex without mutating lastIndex permanently for reuse', () => {
    const re = /foo/g;
    expect(matchesPattern('foo', re)).toBe(true);
    expect(matchesPattern('foo', re)).toBe(true);
  });

  it('matches any item in a readonly list', () => {
    const list = ['a', 'b', 'c'] as const;
    expect(matchesPattern('b', list)).toBe(true);
    expect(matchesPattern('z', list)).toBe(false);
  });

  it('matches via pure predicate', () => {
    expect(matchesPattern('127.0.0.1', (value) => value.startsWith('127.'))).toBe(
      true,
    );
    expect(matchesPattern('10.0.0.1', (value) => value.startsWith('127.'))).toBe(
      false,
    );
  });
});

describe('includesIgnoreCase', () => {
  it('finds substrings case-insensitively', () => {
    expect(includesIgnoreCase('Hello World', 'world')).toBe(true);
    expect(includesIgnoreCase('Hello', 'xyz')).toBe(false);
  });

  it('short-circuits on empty or longer needle', () => {
    expect(includesIgnoreCase('abc', '')).toBe(true);
    expect(includesIgnoreCase('ab', 'abc')).toBe(false);
  });
});
