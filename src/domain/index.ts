export type { JsonPrimitive, JsonArray, JsonObject, JsonValue } from '@/domain/values';
export type {
  HeaderValue,
  HeaderMap,
  QueryValue,
  QueryMap,
  CookieMap,
  UploadedFile,
  FilesBag,
} from '@/domain/values';
export {
  scalarToString,
  jsonToString,
  bodyToString,
  normalizeFiles,
  fileDisplayName,
} from '@/domain/values';

export type {
  MatchPattern,
  MatchPredicate,
  WafField,
  RateLimitSpec,
  FieldCondition,
  AllCondition,
  AnyOfCondition,
  NotCondition,
  WafCondition,
  WafAction,
  WafRule,
  WafPresetName,
  WafConfig,
  WafDecision,
  WafEvaluationResult,
  ProtectionLevel,
} from '@/domain/rules';
export {
  isFieldCondition,
  isAllCondition,
  isAnyOfCondition,
  isNotCondition,
  PROTECTION_LEVELS,
  DEFAULT_PROTECTION_LEVEL,
  DEFAULT_RULE_MIN_LEVEL,
  protectionLevelRank,
  isLevelActive,
  isProtectionLevel,
} from '@/domain/rules';

export type { WafHttpContext, WafAdapter } from '@/domain/context';

export type {
  JsonRegexPattern,
  JsonMatchPattern,
  JsonRateLimitSpec,
  JsonFieldCondition,
  JsonAllCondition,
  JsonAnyOfCondition,
  JsonNotCondition,
  JsonWafCondition,
  JsonWafRule,
  SerializableWafRule,
} from '@/domain/serializable';
