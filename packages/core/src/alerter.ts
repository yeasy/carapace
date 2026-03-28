/**
 * Carapace Core — 告警路由器
 *
 * 将安全事件分发到多个告警渠道（console、webhook、logfile、hook_message）。
 * 内置 5 分钟去重窗口，防止同类事件刷屏。
 * 支持告警升级：重复事件自动提升严重级别。
 * 支持误报驳回：已驳回的事件模式不再告警。
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";

let PKG_VERSION = "unknown";
try {
  PKG_VERSION = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf-8")).version;
} catch { /* fallback to "unknown" if package.json is missing or malformed */ }
import type { SecurityEvent, AlertPayload, AlertSink, Severity } from "./types.js";

// ─── 严重级别排序（用于升级） ─────────────────────────────────────

const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

function upgradeSeverity(current: Severity, levels: number): Severity {
  const idx = SEVERITY_ORDER.indexOf(current);
  const newIdx = Math.min(idx + levels, SEVERITY_ORDER.length - 1);
  return SEVERITY_ORDER[newIdx];
}

// ─── Console Sink ────────────────────────────────────────────────

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "\x1b[41m\x1b[37m", // 白字红底
  high: "\x1b[31m",             // 红色
  medium: "\x1b[33m",           // 黄色
  low: "\x1b[36m",              // 青色
  info: "\x1b[90m",             // 灰色
};
const RESET = "\x1b[0m";

export class ConsoleSink implements AlertSink {
  name = "console";

  async send(payload: AlertPayload): Promise<void> {
    const { event } = payload;
    const color = SEVERITY_COLORS[event.severity];
    const prefix = `${color}[CARAPACE ${event.severity.toUpperCase()}]${RESET}`;
    const action = event.action === "blocked" ? " 🛡️ BLOCKED" : "";

    process.stderr.write(
      `${prefix}${action} ${event.title}\n` +
        `  ${event.description}\n` +
        `  tool=${event.toolName ?? "?"} skill=${event.skillName ?? "?"} rule=${event.ruleName ?? "?"}\n\n`
    );
  }
}

// ─── Webhook Sink ────────────────────────────────────────────────

export class WebhookSink implements AlertSink {
  name = "webhook";
  private maxRetries: number;

  constructor(private url: string, maxRetries: number = 2) {
    // Validate URL to prevent SSRF — only allow http/https
    try {
      const parsed = new URL(url);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        throw new Error(`WebhookSink only supports http/https URLs, got: ${parsed.protocol}`);
      }
    } catch (err) {
      if (err instanceof TypeError) {
        throw new Error(`WebhookSink: invalid URL "${url}"`);
      }
      throw err;
    }
    this.maxRetries = maxRetries;
  }

  async send(payload: AlertPayload): Promise<void> {
    const body = JSON.stringify({
      source: "carapace",
      version: PKG_VERSION,
      event: {
        id: payload.event.id,
        timestamp: new Date(payload.event.timestamp).toISOString(),
        severity: payload.event.severity,
        category: payload.event.category,
        title: payload.event.title,
        description: payload.event.description,
        toolName: payload.event.toolName,
        skillName: payload.event.skillName,
        action: payload.event.action,
      },
    });

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        const resp = await fetch(this.url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body,
          signal: AbortSignal.timeout(5000),
        });
        if (!resp.ok) {
          throw new Error(`HTTP ${resp.status}`);
        }
        return; // 发送成功，立即返回
      } catch (err) {
        if (attempt < this.maxRetries) {
          // 指数退避等待后重试
          await new Promise((r) => setTimeout(r, 500 * 2 ** attempt));
        } else {
          process.stderr.write(
            `[CARAPACE] webhook send failed after ${this.maxRetries + 1} attempts: ${err}\n`
          );
        }
      }
    }
  }
}

// ─── LogFile Sink ────────────────────────────────────────────────

export class LogFileSink implements AlertSink {
  name = "logfile";
  private initPromise: Promise<string | undefined> | null = null;

  constructor(private filePath: string) {}

  async send(payload: AlertPayload): Promise<void> {
    try {
      if (!this.initPromise) {
        this.initPromise = mkdir(dirname(this.filePath), { recursive: true });
      }
      await this.initPromise;
      await appendFile(this.filePath, JSON.stringify(payload.event) + "\n");
    } catch (err) {
      // 写入失败不阻塞，但记录到 stderr 便于排查
      process.stderr.write(`[CARAPACE] logfile write failed: ${err}\n`);
    }
  }
}

// ─── HookMessage Sink ─────────────────────────────────────────────
// 将告警注入 agent 对话，让用户直接在聊天中看到安全告警。
// 回调函数由框架适配器注入（如 OpenClaw 的 hook 系统）。

export type HookMessageCallback = (message: string) => void;

export class HookMessageSink implements AlertSink {
  name = "hook_message";

  constructor(
    private callback: HookMessageCallback,
    /** 最低严重级别，低于此级别不注入对话（默认 high） */
    private minSeverity: Severity = "high"
  ) {}

  async send(payload: AlertPayload): Promise<void> {
    const { event } = payload;

    // 只有达到最低严重级别的事件才注入对话
    if (SEVERITY_ORDER.indexOf(event.severity) < SEVERITY_ORDER.indexOf(this.minSeverity)) {
      return;
    }

    const icon = event.action === "blocked" ? "🛡️" : "⚠️";
    const message =
      `${icon} [Carapace ${event.severity.toUpperCase()}] ${event.title}\n` +
      `${event.description}\n` +
      `规则: ${event.ruleName ?? "unknown"} | 工具: ${event.toolName ?? "unknown"}`;

    try {
      this.callback(message);
    } catch (err) {
      process.stderr.write(`[CARAPACE] hook_message callback failed: ${err}\n`);
    }
  }
}

// ─── 误报驳回管理器 ──────────────────────────────────────────────

export interface DismissalPattern {
  id: string;
  /** 要驳回的规则名（可选，为空则匹配所有规则） */
  ruleName?: string;
  /** 要驳回的工具名（可选） */
  toolName?: string;
  /** 要驳回的 skill 名（可选） */
  skillName?: string;
  /** 驳回原因 */
  reason: string;
  /** 创建时间 */
  createdAt: number;
  /** 过期时间（可选，0 或 undefined 表示永不过期） */
  expiresAt?: number;
}

export class DismissalManager {
  private patterns: DismissalPattern[] = [];

  /**
   * 添加驳回模式
   */
  addDismissal(pattern: DismissalPattern): void {
    // Require at least one filter field to prevent wildcard dismissal that suppresses all alerts
    if (!pattern.ruleName && !pattern.toolName && !pattern.skillName) {
      throw new Error("DismissalPattern must specify at least one of: ruleName, toolName, skillName");
    }
    this.patterns.push(pattern);
  }

  /**
   * 移除驳回模式
   */
  removeDismissal(id: string): boolean {
    const before = this.patterns.length;
    this.patterns = this.patterns.filter((p) => p.id !== id);
    return this.patterns.length < before;
  }

  /**
   * 检查事件是否已被驳回
   */
  isDismissed(event: SecurityEvent): boolean {
    const now = Date.now();
    // Lazily clean up expired patterns when there are many
    if (this.patterns.length > 50) {
      this.cleanupExpired();
    }
    return this.patterns.some((p) => {
      // 检查是否过期
      if (p.expiresAt && p.expiresAt < now) return false;
      // 匹配规则名
      if (p.ruleName && p.ruleName !== event.ruleName) return false;
      // 匹配工具名
      if (p.toolName && p.toolName !== event.toolName) return false;
      // 匹配 skill 名
      if (p.skillName && p.skillName !== event.skillName) return false;
      return true;
    });
  }

  /**
   * 列出所有驳回模式
   */
  listDismissals(): DismissalPattern[] {
    return [...this.patterns];
  }

  /**
   * 清除所有驳回模式
   */
  clearDismissals(): void {
    this.patterns = [];
  }

  /**
   * 清除已过期的驳回模式
   */
  cleanupExpired(): number {
    const now = Date.now();
    const before = this.patterns.length;
    this.patterns = this.patterns.filter((p) => !p.expiresAt || p.expiresAt >= now);
    return before - this.patterns.length;
  }

  get size(): number {
    return this.patterns.length;
  }
}

// ─── 告警升级追踪器 ──────────────────────────────────────────────
// 设计文档 §9.3:
//   首次出现            → 按检测到的严重级别告警
//   10 分钟内 3 次      → 严重级别上升一级
//   10 分钟内 10 次     → 强制为 CRITICAL + 建议启用阻断

interface EscalationEntry {
  timestamps: number[];
}

export interface EscalationConfig {
  /** 升级窗口（毫秒），默认 10 分钟 */
  windowMs?: number;
  /** 触发一级升级的次数阈值，默认 3 */
  tier1Threshold?: number;
  /** 触发强制 CRITICAL 的次数阈值，默认 10 */
  tier2Threshold?: number;
}

export class AlertEscalation {
  private entries = new Map<string, EscalationEntry>();
  private windowMs: number;
  private tier1Threshold: number;
  private tier2Threshold: number;

  constructor(config: EscalationConfig = {}) {
    this.windowMs = config.windowMs ?? 10 * 60 * 1000; // 10 分钟
    this.tier1Threshold = config.tier1Threshold ?? 3;
    this.tier2Threshold = config.tier2Threshold ?? 10;
  }

  /**
   * 评估事件是否需要升级，返回（可能升级后的）严重级别。
   * 同时记录事件出现次数。
   */
  evaluate(event: SecurityEvent): { severity: Severity; escalated: boolean; count: number } {
    const key = this.computeKey(event);
    const now = event.timestamp || Date.now();

    // Periodically clean up stale entries to prevent unbounded growth
    if (this.entries.size > 200) {
      this.cleanup(now);
    }

    if (!this.entries.has(key)) {
      this.entries.set(key, { timestamps: [] });
    }
    const entry = this.entries.get(key)!;

    // 清除窗口外的时间戳
    entry.timestamps = entry.timestamps.filter((t) => now - t < this.windowMs);
    entry.timestamps.push(now);

    const count = entry.timestamps.length;
    let severity = event.severity;
    let escalated = false;

    if (count >= this.tier2Threshold) {
      // 10 次以上 → 强制 CRITICAL
      severity = "critical";
      escalated = event.severity !== "critical";
    } else if (count >= this.tier1Threshold) {
      // 3 次以上 → 上升一级
      severity = upgradeSeverity(event.severity, 1);
      escalated = severity !== event.severity;
    }

    return { severity, escalated, count };
  }

  /**
   * 清理过期条目
   */
  cleanup(now?: number): void {
    const ts = now ?? Date.now();
    for (const [key, entry] of this.entries) {
      entry.timestamps = entry.timestamps.filter((t) => ts - t < this.windowMs);
      if (entry.timestamps.length === 0) {
        this.entries.delete(key);
      }
    }
  }

  get size(): number {
    return this.entries.size;
  }

  private computeKey(event: SecurityEvent): string {
    // 按 rule + tool 分组（不含参数，参数变化不影响升级计数）
    return `${event.ruleName ?? ""}:${event.toolName ?? ""}`;
  }
}

// ─── 告警路由器 ──────────────────────────────────────────────────

export interface AlertRouterConfig {
  /** 启用告警升级 */
  enableEscalation?: boolean;
  /** 升级配置 */
  escalationConfig?: EscalationConfig;
  /** 启用误报驳回 */
  enableDismissal?: boolean;
}

export class AlertRouter {
  private sinks: AlertSink[] = [];
  private dedup = new Map<string, number>();
  private dedupWindowMs = 5 * 60 * 1000; // 5 分钟去重窗口

  /** 告警升级 */
  readonly escalation: AlertEscalation | null;
  /** 误报驳回 */
  readonly dismissal: DismissalManager | null;

  constructor(config?: AlertRouterConfig) {
    this.escalation = config?.enableEscalation !== false
      ? new AlertEscalation(config?.escalationConfig)
      : null;
    this.dismissal = config?.enableDismissal !== false
      ? new DismissalManager()
      : null;
  }

  addSink(sink: AlertSink): void {
    this.sinks.push(sink);
  }

  removeSink(name: string): void {
    this.sinks = this.sinks.filter((s) => s.name !== name);
  }

  /**
   * 发送安全事件到所有已注册的 sink。
   * 流程：驳回检查 → 升级评估（始终计数） → 去重检查 → 分发
   */
  async send(event: SecurityEvent): Promise<void> {
    // 1. 驳回检查
    if (this.dismissal?.isDismissed(event)) {
      return; // 已驳回，不告警
    }

    // 2. 升级评估（必须在去重前执行，以便正确计数重复事件）
    let finalEvent = event;
    if (this.escalation) {
      const result = this.escalation.evaluate(event);
      if (result.escalated) {
        finalEvent = {
          ...event,
          severity: result.severity,
          description: `${event.description} [已升级：${result.count} 次触发]`,
        };
      }
    }

    // 3. 去重检查（升级后的事件也受去重保护，但计数已完成）
    const dedupKey = this.computeDedupKey(event);
    const now = Date.now();
    const lastSeen = this.dedup.get(dedupKey);
    if (lastSeen && now - lastSeen < this.dedupWindowMs) {
      return; // 抑制重复告警
    }
    this.dedup.set(dedupKey, now);
    this.cleanupDedup(now);

    const payload: AlertPayload = {
      event: finalEvent,
      summary: `[${finalEvent.severity.toUpperCase()}] ${finalEvent.title}`,
      actionTaken: finalEvent.action,
    };

    // 4. 并行发送到所有 sink
    await Promise.allSettled(this.sinks.map((sink) => sink.send(payload)));
  }

  private computeDedupKey(event: SecurityEvent): string {
    const raw = `${event.ruleName}:${event.toolName}:${event.matchedPattern ?? ""}`;
    return createHash("sha256").update(raw).digest("hex").slice(0, 16);
  }

  private cleanupDedup(now: number): void {
    if (this.dedup.size < 100) return; // 不频繁清理
    for (const [key, ts] of this.dedup) {
      if (now - ts > this.dedupWindowMs) {
        this.dedup.delete(key);
      }
    }
  }
}
