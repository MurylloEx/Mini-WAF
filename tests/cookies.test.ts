import { describe, expect, it } from 'vitest';
import { parseCookies } from '@/utils/cookies';

describe('parseCookies', () => {
  it('returns empty map for missing or empty header', () => {
    expect(parseCookies(undefined)).toEqual({});
    expect(parseCookies('')).toEqual({});
  });

  it('parses a single cookie', () => {
    expect(parseCookies('session=abc')).toEqual({ session: 'abc' });
  });

  it('parses multiple cookies separated by "; "', () => {
    expect(parseCookies('a=1; b=2; c=3')).toEqual({ a: '1', b: '2', c: '3' });
  });

  it('keeps the first value when a name is repeated', () => {
    expect(parseCookies('id=first; id=second')).toEqual({ id: 'first' });
  });

  it('strips surrounding double quotes from values', () => {
    expect(parseCookies('token="quoted"')).toEqual({ token: 'quoted' });
  });

  it('skips segments without "="', () => {
    expect(parseCookies('alone; ok=1')).toEqual({ ok: '1' });
  });

  it('decodes percent-encoded values by default', () => {
    expect(parseCookies('q=hello%20world')).toEqual({ q: 'hello world' });
  });

  it('falls back to the raw value when decode throws', () => {
    const decode = (): string => {
      throw new URIError('bad');
    };
    expect(parseCookies('x=%E0%A4%A', decode)).toEqual({ x: '%E0%A4%A' });
  });

  it('accepts a custom decoder', () => {
    const decode = (value: string): string => value.toUpperCase();
    expect(parseCookies('role=admin', decode)).toEqual({ role: 'ADMIN' });
  });
});
