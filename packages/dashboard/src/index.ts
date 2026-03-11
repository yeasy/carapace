/**
 * @carapace/dashboard — Web Dashboard, SIEM 连接器, 团队策略管理
 */

export { EventStore } from "./event-store.js";
export type { EventQuery, EventStats, TimeSeriesBucket } from "./event-store.js";

export {
  SplunkSink,
  ElasticSink,
  DatadogSink,
  SyslogSink,
} from "./siem.js";
export type {
  SplunkConfig,
  ElasticConfig,
  DatadogConfig,
  SyslogConfig,
} from "./siem.js";

export {
  PolicyManager,
  POLICY_TEMPLATES,
} from "./policy.js";
export type {
  PolicyDefinition,
  ResolvedPolicy,
} from "./policy.js";

export { DashboardServer } from "./server.js";
export type { DashboardConfig } from "./server.js";
