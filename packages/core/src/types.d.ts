/**
 * Carapace Core — 类型定义
 */
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type EventCategory = "exec_danger" | "path_violation" | "network_suspect" | "rate_anomaly" | "baseline_drift" | "prompt_injection" | "data_exfil";
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
export interface CarapaceConfig {
    blockOnCritical?: boolean;
    alertWebhook?: string;
    logFile?: string;
    sensitivePathPatterns?: string[];
    blockedDomains?: string[];
    maxToolCallsPerMinute?: number;
    enableBaseline?: boolean;
    trustedSkills?: string[];
    licenseKey?: string;
    debug?: boolean;
}
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
//# sourceMappingURL=types.d.ts.map