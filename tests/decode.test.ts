import { Buffer } from 'node:buffer';
import { describe, expect, it } from 'vitest';

import { createMiniWaf } from '@/engine/index';
import {
  expandBase64Candidates,
  expandUrlCandidates,
  extractJsonStringValues,
  extractPathSegments,
} from '@/engine/decode';
import { createMockContext } from './helpers/mock-context';

const b64 = (value: string): string => Buffer.from(value, 'utf8').toString('base64');

describe('expandBase64Candidates', () => {
  const on = { base64: true, url: false };

  it('returns the shared empty array when decoding is off', () => {
    expect(
      expandBase64Candidates([b64('union select 1,2')], { base64: false, url: false }),
    ).toHaveLength(0);
  });

  it('decodes a whole-value base64 blob back to its plaintext', () => {
    const extras = expandBase64Candidates([b64('union select pass from users')], on);
    expect(extras).toEqual(['union select pass from users']);
  });

  it('ignores values shorter than the minimum length', () => {
    // 'abc' -> 'YWJj' (4 chars, valid base64) is below the 16-char floor.
    expect(expandBase64Candidates(['YWJj'], on)).toHaveLength(0);
  });

  it('decodes an unpadded base64 blob (length % 4 in {2, 3})', () => {
    // Encoders like GoTestWAF Base64Flat emit no `=` padding, so the blob
    // length is usually not a multiple of four. It must still decode.
    const unpadded = b64('<body onload=alert(1)>').replace(/=+$/, '');
    expect(unpadded.length % 4).not.toBe(0);
    expect(expandBase64Candidates([unpadded], on)).toEqual([
      '<body onload=alert(1)>',
    ]);
  });

  it('rejects the one impossible base64 length (% 4 === 1)', () => {
    // A remainder of 1 cannot be produced by valid Base64, so it is dropped
    // before any decode attempt.
    const bad = 'A'.repeat(17);
    expect(bad.length % 4).toBe(1);
    expect(expandBase64Candidates([bad], on)).toHaveLength(0);
  });

  it('ignores values carrying non-base64 characters (spaces, dots, dashes)', () => {
    expect(expandBase64Candidates(['union select from a'], on)).toHaveLength(0);
    // JWT-shaped value: the dot separators fail the anchored whole-value shape.
    expect(
      expandBase64Candidates(['eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.ab'], on),
    ).toHaveLength(0);
  });

  it('rejects high-entropy blobs that decode to binary noise', () => {
    // Dashless UUID: valid base64 alphabet, length % 4 === 0, but decodes to
    // non-printable bytes -> dropped before any rescan.
    expect(
      expandBase64Candidates(['550e8400e29b41d4a716446655440000'], on),
    ).toHaveLength(0);
    // Raw random bytes re-encoded as base64 -> non-printable -> dropped.
    const randomBlob = Buffer.from([0, 1, 2, 3, 250, 251, 252, 253, 200, 190, 7, 9])
      .toString('base64');
    expect(expandBase64Candidates([randomBlob], on)).toHaveLength(0);
  });

  it('caps the number of decoded candidates per call', () => {
    const many = Array.from({ length: 40 }, (_, i) =>
      b64(`benign payload number ${i} padded out`),
    );
    expect(expandBase64Candidates(many, on).length).toBeLessThanOrEqual(16);
  });
});

describe('expandUrlCandidates', () => {
  const on = { base64: false, url: true };

  it('returns the shared empty array when url decoding is off', () => {
    expect(
      expandUrlCandidates(['%3Cscript%3E'], { base64: false, url: false }),
    ).toHaveLength(0);
  });

  it('percent-decodes a value that actually changes', () => {
    expect(expandUrlCandidates(['%3Cimg%20src%3Dx%20onerror%3D1%3E'], on)).toEqual([
      '<img src=x onerror=1>',
    ]);
  });

  it('adds nothing for values without a percent escape', () => {
    expect(expandUrlCandidates(['plain value', 'a=b&c=d'], on)).toHaveLength(0);
  });

  it('tolerates a malformed escape without throwing', () => {
    // Lone `%` and `%ZZ` make decodeURIComponent throw — must be swallowed.
    expect(expandUrlCandidates(['100% pure', 'bad %ZZ seq'], on)).toHaveLength(0);
  });

  it('caps the number of decoded candidates per call', () => {
    const many = Array.from({ length: 40 }, (_, i) => `%3Cx${i}%3E`);
    expect(expandUrlCandidates(many, on).length).toBeLessThanOrEqual(16);
  });
});

describe('extractJsonStringValues', () => {
  it('pulls long string leaves from an object', () => {
    const blob = b64('1 UNION SELECT a FROM b');
    expect(extractJsonStringValues(`{"q":"${blob}"}`)).toContain(blob);
  });

  it('walks nested arrays and objects', () => {
    const blob = b64('<body onload=alert(1)> padding here');
    const values = extractJsonStringValues(
      `{"a":{"b":["${blob}"]}}`,
    );
    expect(values).toContain(blob);
  });

  it('drops short strings below the Base64 floor', () => {
    expect(extractJsonStringValues('{"a":"short","b":"tiny"}')).toHaveLength(0);
  });

  it('returns nothing for non-JSON bodies without parsing', () => {
    expect(extractJsonStringValues('name=value&other=thing')).toHaveLength(0);
    expect(extractJsonStringValues('just some free text here')).toHaveLength(0);
    expect(extractJsonStringValues('{ not valid json')).toHaveLength(0);
  });
});

describe('extractPathSegments', () => {
  it('pulls a long path segment out for decoding', () => {
    const blob = b64('<body onload=alert(1)> path payload');
    expect(extractPathSegments(`/download/${blob}`)).toContain(blob);
  });

  it('drops short segments below the Base64 floor', () => {
    expect(extractPathSegments('/a/b/c/short')).toHaveLength(0);
  });

  it('returns nothing for a path with no separator', () => {
    expect(extractPathSegments('nolashere')).toHaveLength(0);
  });
});

describe('engine base64 decode layer', () => {
  const sqliBlob = b64('1 UNION SELECT username, password FROM users');

  it('does not decode at balanced (default off) — raw blob matches nothing', async () => {
    const waf = createMiniWaf({ presets: ['default'], level: 'balanced' });
    const { ctx } = createMockContext({ query: { q: sqliBlob } });
    const result = await waf.handle(ctx);
    expect(result.decision).toBe('allow');
  });

  it('auto-decodes at high and blocks the decoded SQLi', async () => {
    const waf = createMiniWaf({ presets: ['default'], level: 'high' });
    const { ctx } = createMockContext({ query: { q: sqliBlob } });
    const result = await waf.handle(ctx);
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toMatch(/^preset-sqli/);
  });

  it('honours an explicit decode override below high', async () => {
    const waf = createMiniWaf({
      presets: ['default'],
      level: 'balanced',
      decode: { base64: true },
    });
    const { ctx } = createMockContext({ query: { q: sqliBlob } });
    const result = await waf.handle(ctx);
    expect(result.decision).toBe('block');
  });

  it('can be disabled explicitly at high', async () => {
    const waf = createMiniWaf({
      presets: ['default'],
      level: 'high',
      decode: { base64: false },
    });
    const { ctx } = createMockContext({ query: { q: sqliBlob } });
    const result = await waf.handle(ctx);
    expect(result.decision).toBe('allow');
  });

  it('does not rate-limit on decoded key material', async () => {
    // A decoded blob must not change the raw rate-limit key. This only asserts
    // the decode layer is inert for non-matching benign base64 at high.
    const waf = createMiniWaf({ presets: ['default'], level: 'high' });
    const { ctx } = createMockContext({
      query: { data: b64('the quick brown fox jumps over the lazy dog') },
    });
    const result = await waf.handle(ctx);
    expect(result.decision).toBe('allow');
  });

  describe('base64 inside a JSON body value', () => {
    it('decodes a base64 payload carried as a JSON value and blocks it', async () => {
      const waf = createMiniWaf({ presets: ['default'], level: 'high' });
      const { ctx } = createMockContext({
        method: 'POST',
        body: JSON.stringify({ q: sqliBlob }),
      });
      const result = await waf.handle(ctx);
      expect(result.decision).toBe('block');
      expect(result.matchedRule?.id).toMatch(/^preset-sqli/);
    });

    it('decodes a nested JSON value', async () => {
      const waf = createMiniWaf({ presets: ['default'], level: 'high' });
      const xssBlob = b64('<body onload=alert(document.cookie)>');
      const { ctx } = createMockContext({
        method: 'POST',
        body: JSON.stringify({ outer: { list: [xssBlob] } }),
      });
      const result = await waf.handle(ctx);
      expect(result.decision).toBe('block');
    });

    it('does not fire on a benign JSON body at high', async () => {
      const waf = createMiniWaf({ presets: ['default'], level: 'high' });
      const { ctx } = createMockContext({
        method: 'POST',
        body: JSON.stringify({
          sessionId: b64('sid=8f3a2b1c9d0e4f5a6b7c8d9e0f1a2b3c'),
          note: b64('the quarterly report is attached to this thread'),
          avatarHash: '550e8400e29b41d4a716446655440000',
        }),
      });
      const result = await waf.handle(ctx);
      expect(result.decision).toBe('allow');
    });

    it('stays off at balanced', async () => {
      const waf = createMiniWaf({ presets: ['default'], level: 'balanced' });
      const { ctx } = createMockContext({
        method: 'POST',
        body: JSON.stringify({ q: sqliBlob }),
      });
      const result = await waf.handle(ctx);
      expect(result.decision).toBe('allow');
    });
  });

  describe('false positives at high (decode on)', () => {
    const benign: readonly [string, string][] = [
      ['dashless uuid', '550e8400e29b41d4a716446655440000'],
      ['jwt', 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.Zm9vYmFy'],
      ['base64 prose', b64('the quarterly report is attached to this thread')],
      ['base64 email body', b64('Hi team, thanks for the quick turnaround today!')],
      ['opaque session token', b64('sid=8f3a2b1c9d0e4f5a6b7c8d9e0f1a2b3c')],
    ];

    for (const [name, value] of benign) {
      it(`allows ${name}`, async () => {
        const waf = createMiniWaf({ presets: ['default'], level: 'high' });
        const { ctx } = createMockContext({ query: { v: value } });
        const result = await waf.handle(ctx);
        expect(result.decision).toBe('allow');
      });
    }
  });
});

describe('engine url decode layer', () => {
  // Fully percent-encode every byte so the raw form carries no recognizable
  // attack token — only the url decoder can reach the plaintext, isolating the
  // decode layer from rules that already match encoded shapes.
  const fullEnc = (value: string): string =>
    [...Buffer.from(value, 'utf8')]
      .map((b) => `%${b.toString(16).padStart(2, '0')}`)
      .join('');
  const encodedSqli = fullEnc('1 UNION SELECT username, password FROM users');

  it('does not decode at balanced (default off)', async () => {
    const waf = createMiniWaf({ presets: ['default'], level: 'balanced' });
    const { ctx } = createMockContext({ query: { q: encodedSqli } });
    const result = await waf.handle(ctx);
    expect(result.decision).toBe('allow');
  });

  it('auto-decodes at high and blocks the decoded SQLi', async () => {
    const waf = createMiniWaf({ presets: ['default'], level: 'high' });
    const { ctx } = createMockContext({ query: { q: encodedSqli } });
    const result = await waf.handle(ctx);
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toMatch(/^preset-sqli/);
  });

  it('honours an explicit url override below high', async () => {
    const waf = createMiniWaf({
      presets: ['default'],
      level: 'balanced',
      decode: { url: true },
    });
    const { ctx } = createMockContext({ query: { q: encodedSqli } });
    const result = await waf.handle(ctx);
    expect(result.decision).toBe('block');
  });

  it('can be disabled explicitly at high', async () => {
    const waf = createMiniWaf({
      presets: ['default'],
      level: 'high',
      decode: { url: false },
    });
    const { ctx } = createMockContext({ query: { q: encodedSqli } });
    const result = await waf.handle(ctx);
    expect(result.decision).toBe('allow');
  });

  it('decodes a percent-encoded traversal on the URL path', async () => {
    const waf = createMiniWaf({ presets: ['default'], level: 'high' });
    // Encode only the payload tail so it lands as a path segment; the decoded
    // `../../etc/passwd` is what the traversal preset catches.
    const { ctx } = createMockContext({
      path: `/download/${fullEnc('../../../etc/passwd')}`,
    });
    const result = await waf.handle(ctx);
    expect(result.decision).toBe('block');
  });

  it('does not flag a benign percent-encoded path at high', async () => {
    const waf = createMiniWaf({ presets: ['default'], level: 'high' });
    const { ctx } = createMockContext({
      path: '/api/v1/reports/2024%2Fq1%2Fsummary%20final.pdf',
    });
    const result = await waf.handle(ctx);
    expect(result.decision).toBe('allow');
  });

  it('decodes a Base64 payload delivered as a path segment', async () => {
    // The whole path `/download/<blob>` is not a Base64 blob (its `/` breaks the
    // shape); only per-segment extraction reaches the encoded XSS.
    const waf = createMiniWaf({ presets: ['default'], level: 'high' });
    const blob = b64("<body onload=alert('test1')>");
    const { ctx } = createMockContext({ path: `/download/${blob}` });
    const result = await waf.handle(ctx);
    expect(result.decision).toBe('block');
  });

  it('does not flag a benign opaque path segment at high', async () => {
    // A long dashless-hex-ish asset segment must not trip once split out.
    const waf = createMiniWaf({ presets: ['default'], level: 'high' });
    const { ctx } = createMockContext({
      path: '/assets/550e8400e29b41d4a716446655440000/logo.png',
    });
    const result = await waf.handle(ctx);
    expect(result.decision).toBe('allow');
  });
});
