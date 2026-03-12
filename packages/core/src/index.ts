/**
 * @carapace/core — AI Agent 运行时安全监控核心
 */

export * from "./types.js";
export { RuleEngine } from "./engine.js";
export type { EngineResult } from "./engine.js";
export {
  AlertRouter,
  ConsoleSink,
  WebhookSink,
  LogFileSink,
  HookMessageSink,
  AlertEscalation,
  DismissalManager,
} from "./alerter.js";
export type {
  HookMessageCallback,
  DismissalPattern,
  EscalationConfig,
  AlertRouterConfig,
} from "./alerter.js";
export {
  execGuardRule,
  createPathGuardRule,
  createNetworkGuardRule,
  createRateLimiterRule,
  createPromptInjectionRule,
  createDataExfilRule,
  createBaselineDriftRule,
  BaselineTracker,
} from "./rules/index.js";
export type { BaselineConfig, YamlRuleDefinition } from "./rules/index.js";
export { createYamlRule, loadYamlRules, parseSimpleYaml } from "./rules/index.js";
export { generateEventId } from "./utils/id.js";
export {
  StorageBackend,
  MemoryBackend,
  SqliteBackend,
  createStore,
} from "./store.js";
export type {
  StoreConfig,
  EventQuery,
  EventStats,
  TimeSeriesBucket,
  Session,
  SkillBaseline,
} from "./store.js";
