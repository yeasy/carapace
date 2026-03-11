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
export type { BaselineConfig } from "./rules/index.js";
export { generateEventId } from "./utils/id.js";
