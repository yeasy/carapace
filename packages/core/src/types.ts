/**
 * Carapace Core — 类型定义
 */

// ─── 严重级别与事件分类 ──────────────────────────────────────────

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Numeric rank for severity comparison (higher = more severe). */
export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 5, high: 4, medium: 3, low: 2, info: 1,
};

export type EventCategory =
  | "exec_danger"       // 危险 shell 命令
  | "path_violation"    // 敏感文件路径访问
  | "network_suspect"   // 可疑网络活动
  | "rate_anomaly"      // 异常工具调用频率
  | "baseline_drift"    // 行为偏离基线
  | "prompt_injection"  // 潜在 prompt injection
  | "data_exfil";       // 潜在数据外泄

// ─── 安全事件 ────────────────────────────────────────────────────

export interface SecurityEvent {
  id: string;
  timestamp: number;
  category: EventCategory;
  severity: Severity;
  title: string;
  description: string;
  details: Record<string, unknown>;

  toolName?: string;
  toolParams?: Record<string, unknown>;
  skillName?: string;
  sessionId?: string;
  agentId?: string;
  ruleName?: string;
  matchedPattern?: string;
  action: "alert" | "blocked";
}

// ─── 规则系统 ────────────────────────────────────────────────────

export interface RuleContext {
  toolName: string;
  toolParams: Record<string, unknown>;
  toolCallId?: string;
  sessionId?: string;
  agentId?: string;
  skillName?: string;
  timestamp: number;
}

export interface RuleResult {
  triggered: boolean;
  event?: Omit<SecurityEvent, "id" | "timestamp" | "action">;
  shouldBlock?: boolean;
}

export interface SecurityRule {
  name: string;
  description: string;
  check(ctx: RuleContext): RuleResult;
}

// ─── 告警系统 ────────────────────────────────────────────────────

export type AlertChannel = "console" | "webhook" | "logfile" | "hook_message";

export interface AlertPayload {
  event: SecurityEvent;
  summary: string;
  actionTaken: "alert" | "blocked";
}

export interface AlertSink {
  name: string;
  send(payload: AlertPayload): Promise<void>;
}

// ─── 配置 ────────────────────────────────────────────────────────

export interface CarapaceConfig {
  blockOnCritical?: boolean;
  alertWebhook?: string;
  logFile?: string;
  sensitivePathPatterns?: string[];
  blockedDomains?: string[];
  maxToolCallsPerMinute?: number;
  enableBaseline?: boolean;
  trustedSkills?: string[];
  debug?: boolean;
}

// ─── 框架 Adapter 接口 ───────────────────────────────────────────

export interface ToolCallEvent {
  id: string;
  timestamp: number;
  framework: string;
  phase: "before" | "after";
  toolName: string;
  toolParams: Record<string, unknown>;
  toolResult?: unknown;
  toolError?: string;
  durationMs?: number;
  agentId?: string;
  sessionId?: string;
  skillName?: string;
  rawEvent?: unknown;
}

export interface BlockDecision {
  block: boolean;
  blockReason?: string;
  modifiedParams?: Record<string, unknown>;
}

export interface FrameworkAdapter {
  name: string;
  version: string;
  initialize(config: CarapaceConfig): Promise<void>;
  shutdown(): Promise<void>;
}
