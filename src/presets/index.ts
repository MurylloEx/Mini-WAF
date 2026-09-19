import type { WafPresetName, WafRule } from '@/domain/rules';
import { defaultRules } from '@/presets/default';
import { sqliRules } from '@/presets/sqli';
import { xssRules } from '@/presets/xss';
import { scannerRules } from '@/presets/scanners';
import { pathTraversalRules } from '@/presets/path-traversal';
import { rfiRules } from '@/presets/rfi';
import { rceRules } from '@/presets/rce';
import { protocolRules } from '@/presets/protocol';

const PRESET_MAP: Readonly<Record<WafPresetName, readonly WafRule[]>> = {
  default: defaultRules,
  sqli: sqliRules,
  xss: xssRules,
  scanners: scannerRules,
  'path-traversal': pathTraversalRules,
  rfi: rfiRules,
  rce: rceRules,
  protocol: protocolRules,
};

/**
 * Resolve preset names into a flat, immutable rule list (deduped by id).
 * Never mutates the preset source arrays.
 */
export function resolvePresets(
  names: readonly WafPresetName[],
): readonly WafRule[] {
  const seen = new Set<string>();

  return names.flatMap((name) =>
    PRESET_MAP[name].filter((rule) => {
      if (seen.has(rule.id)) {
        return false;
      }
      seen.add(rule.id);
      return true;
    }),
  );
}

export { defaultRules } from '@/presets/default';
export { sqliRules } from '@/presets/sqli';
export { xssRules } from '@/presets/xss';
export { scannerRules } from '@/presets/scanners';
export { pathTraversalRules } from '@/presets/path-traversal';
export { rfiRules } from '@/presets/rfi';
export { rceRules } from '@/presets/rce';
export { protocolRules } from '@/presets/protocol';
