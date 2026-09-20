/**
 * Protection levels control which rules are active.
 *
 * Semântica: cada regra declara um `minLevel`. A regra só é aplicada quando
 * o nível configurado em `WafConfig.level` é **maior ou igual** a esse mínimo
 * (ordenação: low < balanced < high < paranoid).
 *
 * - `low` — alto sinal / baixo FP (scanners óbvios, SQLi clássico, traversal, RFI)
 * - `balanced` — default; low + XSS comum, null-byte, uploads, rate-limit
 * - `high` — balanced + heurísticas agressivas (SSI, hex flood, pollution, SQLi blind)
 * - `paranoid` — high + regras legadas com FP elevado (UA amplas, tags HTML genéricas)
 */

export const PROTECTION_LEVELS = [
  'low',
  'balanced',
  'high',
  'paranoid',
] as const;

export type ProtectionLevel = (typeof PROTECTION_LEVELS)[number];

/** Default when `WafConfig.level` is omitted. */
export const DEFAULT_PROTECTION_LEVEL: ProtectionLevel = 'balanced';

/** Default `minLevel` when a rule omits the field (custom rules stay usable at any level). */
export const DEFAULT_RULE_MIN_LEVEL: ProtectionLevel = 'low';

const LEVEL_RANK: Readonly<Record<ProtectionLevel, number>> = {
  low: 0,
  balanced: 1,
  high: 2,
  paranoid: 3,
};

/**
 * Numeric rank of a protection level, ordered `low` (0) through
 * `paranoid` (3). Useful for comparing two levels directly.
 */
export function protectionLevelRank(level: ProtectionLevel): number {
  return LEVEL_RANK[level];
}

/**
 * True when `configured` is at least as strict as `minLevel`
 * (i.e. rule with that minimum should run).
 */
export function isLevelActive(
  configured: ProtectionLevel,
  minLevel: ProtectionLevel,
): boolean {
  return protectionLevelRank(configured) >= protectionLevelRank(minLevel);
}

/** Type guard: whether an arbitrary string is a valid {@link ProtectionLevel}. */
export function isProtectionLevel(value: string): value is ProtectionLevel {
  return (PROTECTION_LEVELS as readonly string[]).includes(value);
}
