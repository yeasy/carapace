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
  let lastFullCleanup = 0;
  const FULL_CLEANUP_INTERVAL = 5 * 60_000; // 每 5 分钟清理一次空 session
  const MAX_SESSIONS = 10_000; // session Map 上限

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

  // 定期清理空 session 条目和超限淘汰
  function cleanupSessions(now: number): void {
    if (now - lastFullCleanup < FULL_CLEANUP_INTERVAL) return;
    lastFullCleanup = now;
    for (const [key, record] of sessions) {
      if (record.timestamps.length === 0) {
        sessions.delete(key);
      }
    }
    // 超限时淘汰最旧的 session（LRU 近似）
    if (sessions.size > MAX_SESSIONS) {
      const entries = [...sessions.entries()];
      entries.sort((a, b) => {
        const aLast = a[1].timestamps[a[1].timestamps.length - 1] ?? 0;
        const bLast = b[1].timestamps[b[1].timestamps.length - 1] ?? 0;
        return aLast - bLast;
      });
      const toRemove = entries.slice(0, entries.length - MAX_SESSIONS);
      for (const [key] of toRemove) {
        sessions.delete(key);
      }
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
      cleanupSessions(now);

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
