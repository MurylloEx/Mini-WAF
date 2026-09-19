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

Each preset rule already has a `minLevel`; your config `level` decides which ones run.

## Overview (CRS-inspired)

| Preset | Focus | CRS-ish |
|--------|-------|---------|
| `default` | Union of all packs below (order: scanners → protocol → sqli → xss → path-traversal → rfi → rce) | — |
| `sqli` | Classic + advanced SQL injection on query / body / path / cookies | REQUEST-942 |
| `xss` | XSS in query/body/headers, SSI, generic tags, eval/alert | REQUEST-941 (+ SSI) |
| `scanners` | Scanner UAs, null-byte, data exposure, pollution, hex flood, headers, shebang, DoS rate-limit | REQUEST-913 / 912 |
| `path-traversal` | Path traversal + LFI OS / restricted files | REQUEST-930 |
| `rfi` | Remote file include, PHP RCE, dangerous uploads | REQUEST-931 |
| `rce` | Shellshock, unix/windows cmds, SSRF metadata, SSTI, Node RCE, shell expr, fork bomb | REQUEST-932 / 934 |
| `protocol` | Response splitting, smuggling, CRLF, header injection, CL+TE, Host IP, session fixation / ID in URL, empty UA | REQUEST-920 / 921 / 943 |

## Rule ids by preset

Useful for `enabledRuleIds` / `disabledRuleIds`.

### `sqli`

Ids follow `preset-sqli-{classic|advanced}-{query|body|path|cookies}`.

- Classic (`minLevel: 'low'`): UNION/boolean-style patterns
- Advanced (`minLevel: 'high'`): time-based / stacked / schema probes

### `xss`

| Id | Notes |
|----|-------|
| `preset-xss-query` | XSS in query |
| `preset-xss-body` | XSS in body |
| `preset-xss-headers` | XSS in headers |
| `preset-ssi-injection` | Server-side includes |
| `preset-xss-generic-tags` | Broad HTML tags (higher FP; typically higher level) |
| `preset-xss-eval-alert` | `eval` / `alert`-style payloads |

### `scanners`

| Id | Notes |
|----|-------|
| `preset-scanners-ua` | Known scanner User-Agents |
| `preset-scanners-ua-broad` | Broader UA list (more FPs) |
| `preset-null-byte` | Null-byte injection |
| `preset-data-exposure` | Sensitive path / exposure probes |
| `preset-prototype-pollution` | Prototype pollution keys |
| `preset-hex-flood` | Hex flood patterns |
| `preset-excessive-header` | Oversized headers |
| `preset-shebang` | Shebang in payload |
| `preset-dos-rate-limit` | Per-IP rate limit (side effect; disables `decisionCache` when active) |

### `path-traversal`

| Id | Notes |
|----|-------|
| `preset-path-traversal` | `../` style traversal |
| `preset-lfi-os-files` | OS sensitive file paths |
| `preset-lfi-restricted-files` | Restricted app/config files |

### `rfi`

| Id | Notes |
|----|-------|
| `preset-rfi` | Remote file include |
| `preset-rce-php` | PHP RCE-style payloads |
| `preset-dangerous-upload` | Dangerous upload extensions / content |

### `rce`

| Id | Notes |
|----|-------|
| `preset-rce-shellshock` | Shellshock |
| `preset-rce-unix-cmd` | Unix command injection |
| `preset-rce-windows` | Windows command injection |
| `preset-rce-ssrf-metadata` | Cloud metadata SSRF |
| `preset-rce-ssti` | Server-side template injection |
| `preset-rce-nodejs` | Node.js RCE patterns |
| `preset-rce-shell-expression` | Shell `$()` expressions |
| `preset-rce-fork-bomb` | Fork-bomb patterns |

### `protocol`

| Id | Notes |
|----|-------|
| `preset-protocol-response-splitting` | Response splitting |
| `preset-protocol-request-smuggling` | Request smuggling |
| `preset-protocol-crlf-path` | CRLF in path |
| `preset-protocol-header-injection` | Header injection |
| `preset-protocol-cl-te-conflict` | Content-Length / Transfer-Encoding conflict |
| `preset-protocol-host-ip` | Host header as IP literal |
| `preset-session-fixation-cookie-html` | Session fixation via cookie/HTML |
| `preset-session-id-in-url` | Session id in URL |
| `preset-protocol-empty-ua` | Empty User-Agent |

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
