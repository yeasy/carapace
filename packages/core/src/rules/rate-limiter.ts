/**
 * RateLimiter — 工具调用频率异常检测
 *
 * 基于滑动窗口统计每个 session 的工具调用频率，
 * 超过阈值时触发告警，支持按 session 隔离计数。
 */

import type { SecurityRule, RuleContext, RuleResult, Severity } from "../types.js";
import { redactSensitiveValues } from "../utils/redact.js";

interface CallRecord {
  timestamps: number[];
}

function lowerBound(arr: number[], target: number): number {
  let lo = 0, hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (arr[mid] < target) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}

export function createRateLimiterRule(maxCallsPerMinute: number = 60): SecurityRule {
  // Validate parameter to prevent nonsensical behavior
  if (!Number.isFinite(maxCallsPerMinute) || maxCallsPerMinute < 1) {
    maxCallsPerMinute = 60;
  }
  maxCallsPerMinute = Math.floor(maxCallsPerMinute);

  const sessions = new Map<string, CallRecord>();
  let lastFullCleanup = 0;
  const FULL_CLEANUP_INTERVAL = 5 * 60_000; // 每 5 分钟清理一次空 session
  const MAX_SESSIONS = 10_000; // session Map 上限

  // 清理过期记录，防止内存泄漏（保留最近 60 秒）
  function cleanup(record: CallRecord, now: number): void {
    const cutoff = now - 60_000;
    const idx = lowerBound(record.timestamps, cutoff);
    if (idx > 0) {
      record.timestamps = record.timestamps.slice(idx);
    }
  }

  // 定期清理空 session 条目和超限淘汰
  function cleanupSessions(now: number): void {
    if (now - lastFullCleanup < FULL_CLEANUP_INTERVAL) return;
    lastFullCleanup = now;
    // Collect empty keys first, then delete (avoid mutating Map during iteration)
    const emptyKeys: string[] = [];
    for (const [key, record] of sessions) {
      if (record.timestamps.length === 0) {
        emptyKeys.push(key);
      }
    }
    for (const key of emptyKeys) sessions.delete(key);
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
      const now = Number.isFinite(ctx.timestamp) && ctx.timestamp > 0 ? ctx.timestamp : Date.now();

      if (!sessions.has(sessionKey)) {
        sessions.set(sessionKey, { timestamps: [] });
      }

      const record = sessions.get(sessionKey)!;
      // Insert in sorted position so binary search (lowerBound) stays correct
      // even when timestamps arrive out of order.
      const insertIdx = lowerBound(record.timestamps, now);
      if (insertIdx === record.timestamps.length) {
        record.timestamps.push(now);
      } else {
        record.timestamps.splice(insertIdx, 0, now);
      }
      cleanup(record, now);
      cleanupSessions(now);

      // 计算最近 60 秒内的调用数
      const windowStart = now - 60_000;
      const startIdx = lowerBound(record.timestamps, windowStart);
      const recentCalls = record.timestamps.length - startIdx;

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
          toolParams: redactSensitiveValues(ctx.toolParams),
          skillName: ctx.skillName,
          sessionId: ctx.sessionId,
          agentId: ctx.agentId,
        },
      };
    },
  };
}
