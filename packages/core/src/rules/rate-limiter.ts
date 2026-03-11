/**
 * RateLimiter — 工具调用频率异常检测
 *
 * 基于滑动窗口统计每个 session 的工具调用频率，
 * 超过阈值时触发告警，支持按 session 隔离计数。
 */

import type { SecurityRule, RuleContext, RuleResult, Severity } from "../types.js";

interface CallRecord {
  timestamps: number[];
}

export function createRateLimiterRule(maxCallsPerMinute: number = 60): SecurityRule {
  const sessions = new Map<string, CallRecord>();

  // 清理过期记录，防止内存泄漏（保留最近 2 分钟）
  function cleanup(record: CallRecord, now: number): void {
    const cutoff = now - 120_000;
    const idx = record.timestamps.findIndex((t) => t > cutoff);
    if (idx > 0) {
      record.timestamps = record.timestamps.slice(idx);
    } else if (idx === -1) {
      record.timestamps = [];
    }
  }

  return {
    name: "rate-limiter",
    description: "检测异常高频工具调用",

    check(ctx: RuleContext): RuleResult {
      const sessionKey = ctx.sessionId ?? ctx.agentId ?? "__default__";
      const now = ctx.timestamp;

      if (!sessions.has(sessionKey)) {
        sessions.set(sessionKey, { timestamps: [] });
      }

      const record = sessions.get(sessionKey)!;
      record.timestamps.push(now);
      cleanup(record, now);

      // 计算最近 60 秒内的调用数
      const windowStart = now - 60_000;
      const recentCalls = record.timestamps.filter((t) => t > windowStart).length;

      if (recentCalls <= maxCallsPerMinute) {
        return { triggered: false };
      }

      // 判断严重级别：超过 2x 阈值为 critical，1.5x 为 high，其余 medium
      let severity: Severity = "medium";
      if (recentCalls > maxCallsPerMinute * 2) {
        severity = "critical";
      } else if (recentCalls > maxCallsPerMinute * 1.5) {
        severity = "high";
      }

      return {
        triggered: true,
        shouldBlock: severity === "critical",
        event: {
          category: "rate_anomaly",
          severity,
          title: "工具调用频率异常",
          description: `会话 "${sessionKey}" 在 60 秒内调用了 ${recentCalls} 次工具（阈值: ${maxCallsPerMinute}）`,
          details: {
            recentCalls,
            maxCallsPerMinute,
            sessionKey,
            ratio: +(recentCalls / maxCallsPerMinute).toFixed(2),
          },
          toolName: ctx.toolName,
          toolParams: ctx.toolParams,
          skillName: ctx.skillName,
          sessionId: ctx.sessionId,
          agentId: ctx.agentId,
        },
      };
    },
  };
}
