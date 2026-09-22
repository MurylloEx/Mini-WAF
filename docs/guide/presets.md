# Presets

Presets are built-in, immutable `WafRule` packs under `src/presets/*`. Resolve them via `WafConfig.presets` or import arrays from `mini-waf` / `mini-waf/presets`.

## Using presets

```ts
{ presets: ['default'] }
// same as: scanners + protocol + sqli + xss + path-traversal + rfi + rce
```

Individual names: `'sqli' | 'xss' | 'scanners' | 'path-traversal' | 'rfi' | 'rce' | 'protocol' | 'default'`.

```ts
expressWaf({
  level: 'balanced',
  presets: ['sqli', 'xss', 'scanners'],
});
```

`resolvePresets(names)` flattens packs and **dedupes by rule `id`**. Sources are never mutated.

Each preset rule already has a `minLevel`; your config `level` decides which ones run. For reference, here is an actual preset rule verbatim (`src/presets/scanners.ts`), showing the level of detail every preset entry follows:

```ts
{
  id: 'preset-scanners-ua',
  priority: 40,
  action: 'block',
  minLevel: 'low', // active at every level, including the strictest APIs
  reason: 'Known scanner or exploit tool',
  when: {
    field: 'headers.user-agent',
    matches:
      /(?:sqlmap|nikto|nmap|masscan|acunetix|nessus|burpsuite|w3af|dirbuster|owasp_dirbuster|havij|openvas|zgrab|nuclei)/i,
  },
},
```

And the DoS rate-limit rule from the same pack, the one that automatically disables `decisionCache` whenever it is active (see [Security notes](/guide/security)):

```ts
{
  id: 'preset-dos-rate-limit',
  priority: 90,
  action: 'block',
  minLevel: 'balanced',
  reason: 'Possible Denial of Service — request rate exceeded',
  when: {
    field: 'ip',
    rateLimit: { max: 120, windowMs: 60_000, keyPrefix: 'preset-dos' },
  },
},
```

## Overview (CRS-inspired)

| Preset | Rules | Focus | CRS-ish |
|--------|-------|-------|---------|
| `default` | 94 | Union of all packs below (order: scanners → protocol → sqli → xss → path-traversal → rfi → rce) | — |
| `sqli` | 22 | SQL injection (classic, tautology, DBMS primitives, blind, boolean equality, compact subquery, JSON functions, MSSQL `DECLARE`) + NoSQL operator injection (quoted, unquoted, driver API, `$where` time-bomb & timing DoS) | REQUEST-942 |
| `xss` | 14 | XSS in query/body/headers/cookies/path, encoded tags, `data:` URIs, attribute vectors, JS primitives, indirect & breakout sink calls, SSI | REQUEST-941 (+ SSI) |
| `scanners` | 12 | Scanner UAs, LDAP filter & matching-rule injection, GraphQL introspection, null-byte, data exposure, pollution, hex flood, headers, shebang, DoS rate-limit | REQUEST-913 / 912 |
| `path-traversal` | 5 | Plain and encoded traversal, UNC / admin-share paths, LFI OS / restricted files | REQUEST-930 |
| `rfi` | 7 | Stream wrappers, remote script include, PHP include syntax, PHP RCE, XXE, dangerous uploads | REQUEST-931 / 933 |
| `rce` | 19 | Shellshock, JNDI/Log4Shell, unix/windows cmds (incl. `set /a`), reverse shells, fetch-and-exec, LOLBins, SSRF (metadata & internal), SSTI, FreeMarker, Node/lang exec, deserialization (binary & YAML), ASP concat | REQUEST-932 / 934 |
| `protocol` | 15 | Response splitting, smuggling, CRLF (literal, encoded & double-encoded), mail command/verb & IMAP/QUIT injection, header injection, CL+TE, Host IP, session fixation / ID in URL, empty UA | REQUEST-920 / 921 / 943 |

Counts are the full pack; how many actually run depends on your `level`. With
`presets: ['default']` that is **19** rules at `low`, **51** at `balanced`,
**81** at `high` and **94** at `paranoid`.

## Rule ids by preset

Useful for `enabledRuleIds` / `disabledRuleIds`. `min` is the lowest `level` at
which the rule runs.

### `sqli`

| Id | min | Catches |
|----|-----|---------|
| `preset-sqli-classic-{query,body,path,cookies}` | `low` | `UNION SELECT`, `INTERSECT/EXCEPT SELECT`, numeric `OR 1=1` |
| `preset-sqli-dbms-primitives` | `low` | `@@version`, `load_file()`, `INTO OUTFILE`, `xp_cmdshell`, `pg_sleep()`, `openrowset()` |
| `preset-sqli-versioned-comment` | `low` | MySQL `/*!50000…*/` keyword smuggling (URL-borne fields only) |
| `preset-sqli-tautology` | `balanced` | Quoted tautologies: `' OR 'a'='a`, `") OR (1=1` |
| `preset-sqli-select-from` | `balanced` | A whole `SELECT … FROM <table>` in query / path / cookies |
| `preset-sqli-nosql-operator` | `balanced` | MongoDB `{"$ne": null}` auth bypass, `?user[$ne]=null` |
| `preset-sqli-nosql-string` | `balanced` | Unquoted operator form: `$where: '…'`, `, $or: [`, `{$gt: ''}` |
| `preset-sqli-advanced-{query,body,path,cookies}` | `high` | `SLEEP`/`BENCHMARK`/`WAITFOR`, `INFORMATION_SCHEMA`, stacked queries |
| `preset-sqli-boolean-equality` | `high` | Keyword-free numeric test: `AND 1=1`, `OR 6522=6522`, `) AND 12=12` |
| `preset-sqli-compact-subquery` | `high` | Whitespace-free nested subquery: `(select(1)from(users))` |
| `preset-sqli-json-functions` | `high` | JSON accessors: `JSON_EXTRACT(`, `JSON_KEYS(`, `JSON_ARRAYAGG(` |
| `preset-sqli-nosql-driver-api` | `high` | MongoDB driver call: `db.users.find({…})`, `db.coll.aggregate(` |
| `preset-sqli-blind` | `high` | `ORDER BY 9--`, `HAVING 1=1`, `CASE WHEN`, `CHAR(…)` chains, trailing `--` |
| `preset-sqli-nosql-time-dos` | `high` | MongoDB `$where` timing DoS: `new Date() … while(a-b)` busy-wait |
| `preset-sqli-nosql-timebomb` | `paranoid` | MongoDB `$where` JS DoS loop: `while(true)`, `for(;;)` |
| `preset-sqli-mssql-declare` | `paranoid` | T-SQL stacked query: `DECLARE @c varchar(255)` |

### `xss`

| Id | min | Catches |
|----|-----|---------|
| `preset-xss-query` | `balanced` | `<script`, `javascript:`, `on*=`, `document.cookie` in the query string |
| `preset-xss-body` | `balanced` | Same core vectors in the body |
| `preset-xss-headers` | `balanced` | `<script` / `javascript:` in any header |
| `preset-xss-cookies` | `balanced` | Core vectors in cookie values |
| `preset-xss-path` | `balanced` | Core vectors (`javascript:`, `on*=`, `document.cookie`) in the path |
| `preset-xss-encoded-tag` | `balanced` | `%3Cscript`, `&lt;script`, `&#60;script`, `\u003cscript` |
| `preset-xss-dangerous-uri` | `balanced` | `data:text/html`, `data:image/svg+xml`, `data:…javascript` (`data:image/png` is fine) |
| `preset-xss-attribute-vector` | `balanced` | `srcdoc=`, `formaction=`, `xlink:href=`, `expression(`, `attributeName=href` |
| `preset-ssi-injection` | `high` | `<!--#exec`, `<!--#include` and friends (query / body / path / cookies) |
| `preset-xss-js-primitives` | `high` | `String.fromCharCode(`, `atob(`, `Function("`, `window.location`, `sendBeacon(` |
| `preset-xss-indirect-call` | `high` | `alert.call(`, `alert?.(1)` (optional chaining), `` alert`…` ``, `(alert)(1)` |
| `preset-xss-breakout-call` | `high` | String/attr breakout into a sink: `'-alert(1)//`, `");eval(x)` |
| `preset-xss-generic-tags` | `paranoid` | Any `<iframe>`, `<object>`, `<svg>`, `<math>`, `<template>`… |
| `preset-xss-eval-alert` | `paranoid` | `eval(`, `alert(`, `prompt(`, `confirm(` |

### `scanners`

| Id | min | Catches |
|----|-----|---------|
| `preset-scanners-ua` | `low` | Known scanner User-Agents (sqlmap, nikto, nuclei…) |
| `preset-ldap-filter` | `high` | LDAP filter injection: `(&(`, `*)(uid=*`, `(objectClass=*)` |
| `preset-ldap-matching-rule` | `high` | LDAP matching-rule OID bypass: `cn:1.2.840.113556.1.4.803:=2` |
| `preset-null-byte` | `balanced` | Null byte in query / path / body / headers |
| `preset-dos-rate-limit` | `balanced` | Per-IP rate limit (side effect; disables `decisionCache` when active) |
| `preset-data-exposure` | `high` | `phpinfo.php`, `HTTP_RAW_POST_DATA` probes |
| `preset-prototype-pollution` | `high` | `__proto__`, `constructor['prototype']` |
| `preset-hex-flood` | `high` | Long `\xNN` escape runs |
| `preset-scanners-ua-broad` | `paranoid` | Broad UA list (curl, wget, python-requests…) — expect FPs |
| `preset-excessive-header` | `paranoid` | Headers over 2 KB |
| `preset-shebang` | `paranoid` | `#!/bin/sh` in a payload |
| `preset-graphql-introspection` | `paranoid` | `__schema`, `IntrospectionQuery`, `__type(name:` (not `__typename`) |

### `path-traversal`

| Id | min | Catches |
|----|-----|---------|
| `preset-path-traversal` | `low` | `../`, `..\`, `..%2f`, `..;/` |
| `preset-path-traversal-encoded` | `low` | `%2e%2e%2f`, `%252e%252e`, `..%c0%af`, mixed `.%2e/` |
| `preset-lfi-os-files` | `low` | `/etc/passwd`, `boot.ini`, `/proc/self`, `windows/system32` |
| `preset-lfi-unc-path` | `high` | UNC / admin-share path: `\\10.0.0.1\c$\windows` |
| `preset-lfi-restricted-files` | `balanced` | `.git/`, `.env`, `.htaccess`, `wp-config.php`, `id_rsa` |

Adapters expose `path` exactly as it arrived on the wire, so the encoded rule is
what catches `%2e%2e%2f` — the plain one never sees a decoded `..`.

### `rfi`

| Id | min | Catches |
|----|-----|---------|
| `preset-rfi` | `low` | `php://`, `data://`, `expect://`, `zip://`, `phar://`, `file:///`, `allow_url_include` |
| `preset-rce-php` | `low` | `eval(base64_decode(`, `call_user_func_array`, `create_function`, `$_GET[` |
| `preset-rfi-remote-url` | `balanced` | Absolute URL ending in `.php`/`.txt`/`.jsp`/… or a trailing `?` |
| `preset-rfi-include-syntax` | `balanced` | `include('…')`, `require_once $x` |
| `preset-xxe-doctype` | `high` | XXE: `<!DOCTYPE … <!ENTITY … SYSTEM "…">`, external DTD |
| `preset-dangerous-upload` | `balanced` | Upload named `*.php`, `*.jsp`, `*.ps1`, `*.exe`… |
| `preset-upload-extension-bypass` | `balanced` | `shell.php.jpg`, `shell.php\x00.jpg` |

`preset-rfi-remote-url` is deliberately narrow: it does **not** fire on a plain
`https://…` value, so OAuth `redirect_uri`, CDN links and webhook callbacks pass.

### `rce`

| Id | min | Catches |
|----|-----|---------|
| `preset-rce-shellshock` | `low` | `() {` bash function export (CVE-2014-6271) |
| `preset-rce-jndi` | `low` | `${jndi:ldap://…}` and nested `${${lower:j}ndi:…}` (Log4Shell) |
| `preset-rce-unix-cmd` | `low` | `; cat`, `` `whoami` ``, `&& curl`, `$(id)`, `\| wget <arg>` (query / body / cookies / path) |
| `preset-rce-reverse-shell` | `low` | `/dev/tcp/`, `nc -e`, `bash -i >&`, `socat exec:`, `mkfifo … nc` |
| `preset-rce-download-exec` | `low` | `curl … \| sh`, `base64 -d \| bash`, `python -c '…'` |
| `preset-rce-windows-lolbin` | `low` | `certutil -urlcache`, `bitsadmin /transfer`, `mshta http:`, `wmic process call create` |
| `preset-rce-ssrf-metadata` | `low` | `169.254.169.254`, `metadata.google.internal`, other cloud metadata endpoints |
| `preset-rce-windows` | `balanced` | `cmd /c`, `powershell -enc`, `Invoke-Expression` |
| `preset-rce-ssti` | `balanced` | <span v-pre>`{{…}}`</span>, `#{…}`, `<%…%>` with execution indicators |
| `preset-rce-nodejs` | `balanced` | `require('child_process')`, `child_process.exec(` |
| `preset-rce-lang-exec` | `balanced` | `os.system(`, `subprocess.Popen(`, `Runtime.getRuntime().exec(`, `ProcessBuilder(` |
| `preset-rce-freemarker` | `balanced` | FreeMarker injection: `<#assign … ?new()>`, `freemarker.template.utility.Execute` |
| `preset-rce-yaml-deserialization` | `balanced` | Unsafe YAML tags: `!!python/object/apply:`, `!ruby/object`, `!!java` |
| `preset-rce-deserialization` | `balanced` | Java `rO0AB…`, PHP `O:8:"…"`, `pickle.loads(`, `yaml.load(` |
| `preset-rce-shell-expression` | `high` | `$(…)`, `<(…)`, `${IFS}`, `${VAR:-…}` parameter expansion |
| `preset-rce-fork-bomb` | `high` | `:(){ :\|:& };:` |
| `preset-ssrf-internal` | `paranoid` | URL to a private / loopback host: `http://127.0.0.1`, `gopher://10.0.0.5`, `192.168.*` |
| `preset-rce-windows-cmd-set` | `paranoid` | cmd.exe primitive: `set /a 3482*7301`, `set /p x=` |
| `preset-rce-asp-concat` | `paranoid` | VBScript/ASP concat obfuscation: `Ex"&"e"&"cute`, `e'+'v'+'al` |

`preset-rce-shell-expression` ignores plain `${name}` interpolation, so i18n and
price templates do not trip it — only shell expansion operators do.

### `protocol`

| Id | min | Catches |
|----|-----|---------|
| `preset-protocol-response-splitting` | `balanced` | CR/LF followed by `Content-Type:`, `Set-Cookie:`, `Location:` |
| `preset-protocol-request-smuggling` | `balanced` | A full request line (`GET / HTTP/1.1`) inside a value |
| `preset-protocol-crlf-path` | `balanced` | CR/LF in the request path |
| `preset-protocol-crlf-encoded-path` | `balanced` | Percent-encoded CR/LF in path / URL: `%0d%0a`, `%0aSet-Cookie:` |
| `preset-protocol-crlf-double-encoded` | `balanced` | Double-encoded / overlong CR/LF: `%250d%250a`, `%c0%8a` |
| `preset-protocol-mail-command` | `high` | CR/LF + SMTP/IMAP verb: `\r\nRCPT TO`, `%0aMAIL FROM`, `EHLO`, `AUTH LOGIN` |
| `preset-protocol-imap-command` | `high` | CR/LF + tagged IMAP command: `\r\nV100 CAPABILITY`, `V101 FETCH 4791` |
| `preset-protocol-mail-teardown` | `high` | Mail session teardown alone on its line: `\r\nQUIT\r\n` |
| `preset-protocol-mail-verb` | `paranoid` | SMTP/IMAP verb without CR/LF: `RCPT TO:`, `MAIL FROM:`, `EHLO host` |
| `preset-session-fixation-cookie-html` | `balanced` | `.cookie … expires=`, `http-equiv=set-cookie` |
| `preset-protocol-header-injection` | `high` | CR/LF + `Location:` / `X-Forwarded-For:` in the query |
| `preset-protocol-cl-te-conflict` | `high` | `Content-Length` and `Transfer-Encoding` both present |
| `preset-protocol-host-ip` | `high` | `Host` header is a raw IP literal |
| `preset-session-id-in-url` | `high` | `PHPSESSID=`, `jsessionid=`, `connect.sid=` in the URL |
| `preset-protocol-empty-ua` | `paranoid` | Empty or missing `User-Agent` |

## What the presets do **not** cover

Worth knowing before you rely on them:

- **Query parameter names are not scanned** — only values. With a non-nesting
  query parser (Express 5's default) `?user[$ne]=null` keeps the payload in the
  key and slips through. Set `query parser` to `extended` on Express 5 (it is
  the default on Express 4) and the nested object is flattened and inspected.
- **Response bodies are never inspected** — this is a request-side WAF.
- **No decoding pass.** Rules match what the framework hands over, plus explicit
  encoded variants where it matters (traversal, XSS tags). A payload encoded in
  a scheme no rule anticipates will pass.
- **No cross-request correlation** beyond the per-IP rate limit.

## Importing presets directly

```ts
import {
  resolvePresets,
  defaultRules,
  sqliRules,
  xssRules,
  scannerRules,
  pathTraversalRules,
  rfiRules,
  rceRules,
  protocolRules,
} from 'mini-waf/presets';

const rules = resolvePresets(['sqli', 'xss']);
```

Or from the root package: the same symbols are re-exported via `mini-waf`.
