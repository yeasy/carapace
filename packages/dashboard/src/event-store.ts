/**
 * 事件存储 — 内存事件数据库，支持查询和聚合
 */

import type { SecurityEvent, Severity, EventCategory } from "@carapace/core";

export interface EventQuery {
  category?: EventCategory;
  severity?: Severity;
  ruleName?: string;
  sessionId?: string;
  skillName?: string;
  since?: number;
  until?: number;
  limit?: number;
  offset?: number;
}

export interface EventStats {
  total: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<string, number>;
  byRule: Record<string, number>;
  blockedCount: number;
  alertCount: number;
  timeRange: { first: number; last: number } | null;
}

export interface TimeSeriesBucket {
  timestamp: number;
  count: number;
  blocked: number;
}

export class EventStore {
  private events: SecurityEvent[] = [];
  private maxEvents: number;

  constructor(maxEvents = 10000) {
    this.maxEvents = maxEvents;
  }

  /**
   * 添加事件
   */
  add(event: SecurityEvent): void {
    this.events.push(event);
    // Batch eviction with 10% headroom (min 100) to avoid O(n) slice on every insert
    const headroom = Math.max(Math.ceil(this.maxEvents * 0.1), 100);
    if (this.events.length > this.maxEvents + headroom) {
      this.events = this.events.slice(-this.maxEvents);
    }
  }

  /**
   * 批量添加
   */
  addBatch(events: SecurityEvent[]): void {
    for (const e of events) this.add(e);
  }

  /**
   * 查询事件
   */
  query(q: EventQuery = {}): SecurityEvent[] {
    // Single-pass filter to avoid chained .filter() allocations
    const hasFilters = q.category !== undefined || q.severity !== undefined || q.ruleName !== undefined || q.sessionId !== undefined || q.skillName !== undefined || q.since !== undefined || q.until !== undefined;
    const result = hasFilters
      ? this.events.filter((e) =>
          (q.category === undefined || e.category === q.category) &&
          (q.severity === undefined || e.severity === q.severity) &&
          (q.ruleName === undefined || e.ruleName === q.ruleName) &&
          (q.sessionId === undefined || e.sessionId === q.sessionId) &&
          (q.skillName === undefined || e.skillName === q.skillName) &&
          (q.since === undefined || e.timestamp >= q.since) &&
          (q.until === undefined || e.timestamp <= q.until))
      : this.events.slice();

    // 按时间倒序（events are appended chronologically, so reverse is O(n) vs sort O(n log n))
    result.reverse();

    const offset = q.offset ?? 0;
    const limit = Math.min(q.limit ?? 100, 10000);
    return result.slice(offset, offset + limit);
  }

  /**
   * 统计信息
   */
  getStats(since?: number): EventStats {
    const events = since !== undefined
      ? this.events.filter((e) => e.timestamp >= since)
      : this.events;

    const bySeverity: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    const byCategory: Record<string, number> = {};
    const byRule: Record<string, number> = {};
    let blockedCount = 0;
    let alertCount = 0;
    let firstTs = Number.MAX_SAFE_INTEGER;
    let lastTs = 0;

    for (const e of events) {
      bySeverity[e.severity] = (bySeverity[e.severity] ?? 0) + 1;
      byCategory[e.category] = (byCategory[e.category] ?? 0) + 1;
      if (e.ruleName) byRule[e.ruleName] = (byRule[e.ruleName] ?? 0) + 1;
      if (e.action === "blocked") blockedCount++;
      else alertCount++;
      if (e.timestamp < firstTs) firstTs = e.timestamp;
      if (e.timestamp > lastTs) lastTs = e.timestamp;
    }

    return {
      total: events.length,
      bySeverity: bySeverity as Record<Severity, number>,
      byCategory,
      byRule,
      blockedCount,
      alertCount,
      timeRange:
        events.length > 0
          ? { first: firstTs, last: lastTs }
          : null,
    };
  }

  /**
   * 时间序列聚合（按分钟/小时/天分桶）
   */
  timeSeries(bucketMs: number = 60_000, since?: number): TimeSeriesBucket[] {
    const events = since !== undefined
      ? this.events.filter((e) => e.timestamp >= since)
      : this.events;

    if (events.length === 0) return [];

    const buckets = new Map<number, { count: number; blocked: number }>();

    for (const e of events) {
      const key = Math.floor(e.timestamp / bucketMs) * bucketMs;
      const bucket = buckets.get(key) ?? { count: 0, blocked: 0 };
      bucket.count++;
      if (e.action === "blocked") bucket.blocked++;
      buckets.set(key, bucket);
    }

    return Array.from(buckets.entries())
      .sort(([a], [b]) => a - b)
      .map(([timestamp, data]) => ({
        timestamp,
        count: data.count,
        blocked: data.blocked,
      }));
  }

  /**
   * 清空所有事件
   */
  clear(): void {
    this.events = [];
  }

  /**
   * 获取事件总数
   */
  get size(): number {
    return this.events.length;
  }
}
