import { describe, expect, it } from 'vitest';
import { createWafEngine } from '@/engine/engine';
import { createMockContext } from './helpers/mock-context';

describe('presets XSS / SQLi / scanners', () => {
  it('blocks XSS via default preset', async () => {
    const engine = createWafEngine(
      { presets: ['xss'] },
    );
    const mock = createMockContext({
      query: { q: '<script>alert(1)</script>' },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toMatch(/xss/);
  });

  it('blocks SSI injection via xss preset at high', async () => {
    const engine = createWafEngine(
      { presets: ['xss'], level: 'high' },
    );
    const mock = createMockContext({
      query: { page: '<!--#exec cmd="id"-->' },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toBe('preset-ssi-injection');
  });

  it('blocks SQLi via sqli preset', async () => {
    const engine = createWafEngine(
      { presets: ['sqli'] },
    );
    const mock = createMockContext({
      query: { id: '1 UNION SELECT password FROM users' },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toMatch(/sqli/);
  });

  it('blocks stacked / WAITFOR SQLi at high', async () => {
    const engine = createWafEngine(
      { presets: ['sqli'], level: 'high' },
    );
    const mock = createMockContext({
      query: { id: "1'; WAITFOR DELAY '0:0:5'" },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
  });

  it('blocks scanners by user-agent', async () => {
    const engine = createWafEngine(
      { presets: ['scanners'] },
    );
    const mock = createMockContext({
      headers: { 'user-agent': 'sqlmap/1.7' },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toBe('preset-scanners-ua');
  });

  it('blocks prototype pollution at high', async () => {
    const engine = createWafEngine(
      { presets: ['scanners'], level: 'high' },
    );
    const mock = createMockContext({
      body: '{"__proto__":{"admin":true}}',
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toBe('preset-prototype-pollution');
  });

  it('blocks PHP RCE via rfi preset', async () => {
    const engine = createWafEngine(
      { presets: ['rfi'] },
    );
    const mock = createMockContext({
      query: { cmd: 'eval(base64_decode("YQ=="))' },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toBe('preset-rce-php');
  });

  it('blocks dangerous upload extensions', async () => {
    const engine = createWafEngine(
      { presets: ['rfi'] },
    );
    const mock = createMockContext({
      files: [{ originalname: 'shell.php' }],
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toBe('preset-dangerous-upload');
  });

  it('allows benign traffic on default preset', async () => {
    const engine = createWafEngine(
      { presets: ['default'] },
    );
    const mock = createMockContext({
      path: '/api/users',
      query: { page: '1' },
      headers: { 'user-agent': 'Mozilla/5.0' },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('allow');
  });

  it('blocks Unix command injection via rce preset', async () => {
    const engine = createWafEngine(
      { presets: ['rce'] },
    );
    const mock = createMockContext({
      query: { cmd: '; cat /etc/passwd' },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toBe('preset-rce-unix-cmd');
  });

  it('blocks cloud metadata SSRF via rce preset', async () => {
    const engine = createWafEngine(
      { presets: ['rce'] },
    );
    const mock = createMockContext({
      query: { url: 'http://169.254.169.254/latest/meta-data/' },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toBe('preset-rce-ssrf-metadata');
  });

  it('blocks SSTI via rce preset at balanced', async () => {
    const engine = createWafEngine(
      { presets: ['rce'], level: 'balanced' },
    );
    const mock = createMockContext({
      query: { tpl: '{{7*7}}' },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toBe('preset-rce-ssti');
  });

  it('blocks HTTP response splitting via protocol preset', async () => {
    const engine = createWafEngine(
      { presets: ['protocol'], level: 'balanced' },
    );
    const mock = createMockContext({
      query: { q: 'x\r\nSet-Cookie: session=evil' },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toBe('preset-protocol-response-splitting');
  });

  it('blocks CL+TE conflict via protocol preset at high', async () => {
    const engine = createWafEngine(
      { presets: ['protocol'], level: 'high' },
    );
    const mock = createMockContext({
      headers: {
        'user-agent': 'Mozilla/5.0',
        'content-length': '10',
        'transfer-encoding': 'chunked',
      },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toBe('preset-protocol-cl-te-conflict');
  });

  it('blocks Host IP literals (IPv4 and IPv6) at high', async () => {
    const engine = createWafEngine(
      { presets: ['protocol'], level: 'high' },
    );

    const v4 = await engine.handle(
      createMockContext({
        headers: { host: '127.0.0.1:3000', 'user-agent': 'Mozilla/5.0' },
      }).ctx,
    );
    expect(v4.decision).toBe('block');
    expect(v4.matchedRule?.id).toBe('preset-protocol-host-ip');

    const v6 = await engine.handle(
      createMockContext({
        headers: { host: '[2001:db8::1]:443', 'user-agent': 'Mozilla/5.0' },
      }).ctx,
    );
    expect(v6.decision).toBe('block');
    expect(v6.matchedRule?.id).toBe('preset-protocol-host-ip');
  });

  it('blocks OS file LFI via path-traversal preset', async () => {
    const engine = createWafEngine(
      { presets: ['path-traversal'] },
    );
    const mock = createMockContext({
      query: { file: '/etc/passwd' },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toBe('preset-lfi-os-files');
  });
});
