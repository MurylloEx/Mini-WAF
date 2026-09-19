import type { WafRule } from '@/domain/rules';
import { sqliRules } from '@/presets/sqli';
import { xssRules } from '@/presets/xss';
import { scannerRules } from '@/presets/scanners';
import { pathTraversalRules } from '@/presets/path-traversal';
import { rfiRules } from '@/presets/rfi';
import { rceRules } from '@/presets/rce';
import { protocolRules } from '@/presets/protocol';

/** Combined baseline pack used by `presets: ['default']`. */
export const defaultRules: readonly WafRule[] = [
  ...scannerRules,
  ...protocolRules,
  ...sqliRules,
  ...xssRules,
  ...pathTraversalRules,
  ...rfiRules,
  ...rceRules,
];
