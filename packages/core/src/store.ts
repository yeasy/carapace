/**
 * 存储后端 — 支持内存和 SQLite 持久化
 */

import type { SecurityEvent, Severity, EventCategory } from "./types.js";
import type { DismissalPattern } from "./alerter.js";

/** Minimal type for better-sqlite3 Statement (optional dependency) */
interface SqliteStatement {
  run(...params: unknown[]): { changes: number };
  get(...params: unknown[]): SqliteRow | undefined;
  all(...params: unknown[]): SqliteRow[];
}

/** Minimal type for better-sqlite3 Database (optional dependency) */
interface SqliteDatabase {
  pragma(pragma: string): unknown;
  exec(sql: string): void;
  prepare(sql: string): SqliteStatement;
  close(): void;
}

/** Generic row type for better-sqlite3 query results */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type SqliteRow = Record<string, any>;
// Note: ideally SqliteRow would be Record<string, unknown>, but better-sqlite3
// returns Record<string, any> and changing it would require casts at every access.
// Keeping as-is for compatibility with the driver's own typings.

/** Safe JSON.parse that returns fallback on error instead of throwing */
function safeJsonParse<T>(json: string | null | undefined, fallback: T): T {
  if (!json) return fallback;
  try {
    return JSON.parse(json);
  } catch {
    return fallback;
  }
}

// ─── 配置与接口 ──────────────────────────────────────────────────

export interface StoreConfig {
  type?: "sqlite" | "memory";
  sqlitePath?: string;
  maxEvents?: number;
}

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

export interface Session {
  sessionId: string;
  agentId?: string;
  startedAt: number;
  endedAt?: number;
  toolCallCount: number;
  eventCount: number;
  skillsUsed?: string[];
}

export interface SkillBaseline {
  skillName: string;
  firstSeen: number;
  lastSeen: number;
  sessionCount: number;
  toolUsage?: Record<string, number>;
  pathPatterns?: string[];
  domainPatterns?: string[];
  commandPatterns?: string[];
  avgCallsPerSession: number;
  stdDevCalls: number;
  maxCallsObserved: number;
}

/**
 * 抽象存储后端接口
 */
export abstract class StorageBackend {
  abstract addEvent(event: SecurityEvent): Promise<void>;
  abstract getEventById(id: string): Promise<SecurityEvent | null>;
  abstract queryEvents(query: EventQuery): Promise<SecurityEvent[]>;
  abstract getStats(since?: number): Promise<EventStats>;
  abstract timeSeries(
    bucketMs?: number,
    since?: number
  ): Promise<TimeSeriesBucket[]>;

  abstract addSession(session: Session): Promise<void>;
  abstract updateSession(sessionId: string, updates: Partial<Session>): Promise<void>;
  abstract getSession(sessionId: string): Promise<Session | null>;

  abstract saveBaseline(baseline: SkillBaseline): Promise<void>;
  abstract getBaseline(skillName: string): Promise<SkillBaseline | null>;
  abstract listBaselines(): Promise<SkillBaseline[]>;

  abstract addDismissal(pattern: DismissalPattern): Promise<void>;
  abstract removeDismissal(id: string): Promise<boolean>;
  abstract listDismissals(): Promise<DismissalPattern[]>;
  abstract clearDismissals(): Promise<void>;

  abstract clear(): Promise<void>;
  abstract close(): Promise<void>;
}

// ─── 内存后端 ────────────────────────────────────────────────────

export class MemoryBackend extends StorageBackend {
  private events: SecurityEvent[] = [];
  private sessions: Map<string, Session> = new Map();
  private baselines: Map<string, SkillBaseline> = new Map();
  private dismissals: Map<string, DismissalPattern> = new Map();
  private maxEvents: number;
  private maxSessions: number;

  constructor(maxEvents = 10000, maxSessions = 10000) {
    super();
    this.maxEvents = Math.max(maxEvents, 1);
    this.maxSessions = Math.max(maxSessions, 1);
  }

  async addEvent(event: SecurityEvent): Promise<void> {
    this.events.push(event);
    // Batch eviction: trim when buffer exceeds capacity + headroom to avoid copying on every insert
    const headroom = Math.min(Math.floor(this.maxEvents * 0.5), 500);
    if (this.events.length > this.maxEvents + headroom) {
      this.events = this.events.slice(-this.maxEvents);
    }
  }

  async getEventById(id: string): Promise<SecurityEvent | null> {
    return this.events.find((e) => e.id === id) ?? null;
  }

  async queryEvents(query: EventQuery = {}): Promise<SecurityEvent[]> {
    // Single-pass filter to avoid chained .filter() allocations
    const hasFilters = query.category !== undefined || query.severity !== undefined || query.ruleName !== undefined || query.sessionId !== undefined || query.skillName !== undefined || query.since !== undefined || query.until !== undefined;
    const result = hasFilters
      ? this.events.filter((e) =>
          (query.category === undefined || e.category === query.category) &&
          (query.severity === undefined || e.severity === query.severity) &&
          (query.ruleName === undefined || e.ruleName === query.ruleName) &&
          (query.sessionId === undefined || e.sessionId === query.sessionId) &&
          (query.skillName === undefined || e.skillName === query.skillName) &&
          (query.since === undefined || e.timestamp >= query.since) &&
          (query.until === undefined || e.timestamp <= query.until))
      : this.events.slice();

    // 按时间倒序（events are appended chronologically, so reverse is O(n) vs sort O(n log n))
    result.reverse();

    const offset = query.offset ?? 0;
    const limit = Math.min(query.limit ?? 100, 10000);
    return result.slice(offset, offset + limit);
  }

  async getStats(since?: number): Promise<EventStats> {
    const events = since !== undefined ? this.events.filter((e) => e.timestamp >= since) : this.events;

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
      if (e.action === "alert") alertCount++;
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

  async timeSeries(
    bucketMs: number = 60_000,
    since?: number
  ): Promise<TimeSeriesBucket[]> {
    bucketMs = Math.floor(bucketMs);
    if (bucketMs <= 0) throw new Error("bucketMs must be positive");
    const events = since !== undefined ? this.events.filter((e) => e.timestamp >= since) : this.events;

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

  async addSession(session: Session): Promise<void> {
    this.sessions.set(session.sessionId, session);
    // Batch eviction with headroom to amortize cost
    const HEADROOM = 500;
    if (this.sessions.size > this.maxSessions + HEADROOM) {
      const toRemove = this.sessions.size - this.maxSessions;
      // Collect keys first, then delete (avoid mutating Map during iteration)
      const keysToRemove: string[] = [];
      for (const key of this.sessions.keys()) {
        if (keysToRemove.length >= toRemove) break;
        keysToRemove.push(key);
      }
      for (const key of keysToRemove) this.sessions.delete(key);
    }
  }

  async updateSession(sessionId: string, updates: Partial<Session>): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session) {
      // Prevent sessionId override which would corrupt the map key → value mapping
      const { sessionId: _ignored, ...safeUpdates } = updates;
      this.sessions.set(sessionId, { ...session, ...safeUpdates });
    }
  }

  async getSession(sessionId: string): Promise<Session | null> {
    return this.sessions.get(sessionId) ?? null;
  }

  async saveBaseline(baseline: SkillBaseline): Promise<void> {
    // Evict oldest baseline if at capacity (prevent unbounded growth)
    const MAX_BASELINES = 1000;
    if (!this.baselines.has(baseline.skillName) && this.baselines.size >= MAX_BASELINES) {
      // Remove the first (oldest-inserted) entry
      const firstKey = this.baselines.keys().next().value;
      if (firstKey !== undefined) this.baselines.delete(firstKey);
    }
    this.baselines.set(baseline.skillName, baseline);
  }

  async getBaseline(skillName: string): Promise<SkillBaseline | null> {
    return this.baselines.get(skillName) ?? null;
  }

  async listBaselines(): Promise<SkillBaseline[]> {
    return [...this.baselines.values()];
  }

  async addDismissal(pattern: DismissalPattern): Promise<void> {
    this.dismissals.set(pattern.id, pattern);
  }

  async removeDismissal(id: string): Promise<boolean> {
    return this.dismissals.delete(id);
  }

  async listDismissals(): Promise<DismissalPattern[]> {
    const now = Date.now();
    // Collect expired IDs first, then delete (avoid mutating during iteration)
    const expired: string[] = [];
    for (const [id, p] of this.dismissals) {
      if (p.expiresAt && p.expiresAt < now) {
        expired.push(id);
      }
    }
    for (const id of expired) this.dismissals.delete(id);
    return [...this.dismissals.values()];
  }

  async clearDismissals(): Promise<void> {
    this.dismissals.clear();
  }

  async clear(): Promise<void> {
    this.events = [];
    this.sessions.clear();
    this.baselines.clear();
    this.dismissals.clear();
  }

  async close(): Promise<void> {
    // 内存后端无需清理
  }
}

// ─── SQLite 后端 ─────────────────────────────────────────────────

export class SqliteBackend extends StorageBackend {
  private db!: SqliteDatabase;
  private initialized = false;
  private initPromise: Promise<void> | null = null;
  private insertCount = 0;
  private closed = false;
  private maxEvents: number;

  constructor(dbPath: string = ":memory:", maxEvents: number = 100_000) {
    super();
    // 延迟初始化，在实际使用时再导入 better-sqlite3
    this.dbPath = dbPath;
    this.maxEvents = maxEvents;
  }

  private dbPath: string;

  private ensureOpen(): void {
    if (this.closed) throw new Error("SqliteBackend is closed");
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;
    // Guard against concurrent initialization
    if (this.initPromise) return this.initPromise;
    this.initPromise = this.doInitialize();
    return this.initPromise;
  }

  private async doInitialize(): Promise<void> {

    try {
      // 动态导入 better-sqlite3，允许其作为可选依赖
      // @ts-ignore - optional dependency
      const DatabaseSync = (await import("better-sqlite3")).default;
      this.db = new DatabaseSync(this.dbPath);
      this.db.pragma("journal_mode = WAL");
      this.db.pragma("synchronous = NORMAL");

      // 创建表
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS events (
          id TEXT PRIMARY KEY,
          timestamp INTEGER NOT NULL,
          category TEXT NOT NULL,
          severity TEXT NOT NULL,
          title TEXT NOT NULL,
          description TEXT,
          tool_name TEXT,
          skill_name TEXT,
          session_id TEXT,
          agent_id TEXT,
          rule_name TEXT,
          matched_pattern TEXT,
          action TEXT NOT NULL,
          details_json TEXT,
          tool_params_json TEXT,
          created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000)
        );

        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
        CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
        CREATE INDEX IF NOT EXISTS idx_events_skill ON events(skill_name);

        CREATE TABLE IF NOT EXISTS skill_baselines (
          skill_name TEXT PRIMARY KEY,
          first_seen INTEGER NOT NULL,
          last_seen INTEGER NOT NULL,
          session_count INTEGER DEFAULT 0,
          tool_usage_json TEXT,
          path_patterns_json TEXT,
          domain_patterns_json TEXT,
          command_patterns_json TEXT,
          avg_calls_per_session REAL DEFAULT 0,
          std_dev_calls REAL DEFAULT 0,
          max_calls_observed INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS sessions (
          session_id TEXT PRIMARY KEY,
          agent_id TEXT,
          started_at INTEGER NOT NULL,
          ended_at INTEGER,
          tool_call_count INTEGER DEFAULT 0,
          event_count INTEGER DEFAULT 0,
          skills_used_json TEXT
        );

        CREATE TABLE IF NOT EXISTS dismissals (
          id TEXT PRIMARY KEY,
          rule_name TEXT,
          tool_name TEXT,
          skill_name TEXT,
          reason TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          expires_at INTEGER
        );
      `);

      this.initialized = true;
    } catch (error) {
      // Close leaked db handle before retrying
      if (this.db) {
        try { this.db.close(); } catch { /* ignore close error */ }
        this.db = null as unknown as import("better-sqlite3").Database;
      }
      // Reset so next call can retry
      this.initPromise = null;
      throw new Error(
        `Failed to initialize SQLite backend: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  async addEvent(event: SecurityEvent): Promise<void> {
    this.ensureOpen();
    await this.initialize();

    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO events (id, timestamp, category, severity, title, description, tool_name, skill_name, session_id, agent_id, rule_name, matched_pattern, action, details_json, tool_params_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      event.id,
      event.timestamp,
      event.category,
      event.severity,
      event.title,
      event.description,
      event.toolName,
      event.skillName,
      event.sessionId,
      event.agentId,
      event.ruleName,
      event.matchedPattern,
      event.action,
      JSON.stringify(event.details),
      event.toolParams ? JSON.stringify(event.toolParams) : null
    );

    // Periodic eviction: every 1000 inserts, check if we exceed maxEvents
    this.insertCount++;
    if (this.insertCount % 1000 === 0) {
      const countRow = this.db.prepare("SELECT COUNT(*) as cnt FROM events").get() as SqliteRow;
      if (countRow.cnt > this.maxEvents) {
        const excess = countRow.cnt - this.maxEvents;
        this.db.prepare(
          "DELETE FROM events WHERE id IN (SELECT id FROM events ORDER BY timestamp ASC LIMIT ?)"
        ).run(excess);
      }
    }
  }

  async getEventById(id: string): Promise<SecurityEvent | null> {
    this.ensureOpen();
    await this.initialize();

    const stmt = this.db.prepare("SELECT * FROM events WHERE id = ?");
    const row = stmt.get(id) as SqliteRow;
    if (!row) return null;

    return {
      id: row.id,
      timestamp: row.timestamp,
      category: row.category as EventCategory,
      severity: row.severity as Severity,
      title: row.title,
      description: row.description,
      details: safeJsonParse(row.details_json, {}),
      toolName: row.tool_name ?? undefined,
      toolParams: safeJsonParse(row.tool_params_json, undefined),
      skillName: row.skill_name ?? undefined,
      sessionId: row.session_id ?? undefined,
      agentId: row.agent_id ?? undefined,
      ruleName: row.rule_name ?? undefined,
      matchedPattern: row.matched_pattern ?? undefined,
      action: row.action as "alert" | "blocked",
    };
  }

  async queryEvents(query: EventQuery = {}): Promise<SecurityEvent[]> {
    this.ensureOpen();
    await this.initialize();

    let sql = "SELECT * FROM events WHERE 1=1";
    const params: unknown[] = [];

    if (query.category !== undefined) {
      sql += " AND category = ?";
      params.push(query.category);
    }
    if (query.severity !== undefined) {
      sql += " AND severity = ?";
      params.push(query.severity);
    }
    if (query.ruleName !== undefined) {
      sql += " AND rule_name = ?";
      params.push(query.ruleName);
    }
    if (query.sessionId !== undefined) {
      sql += " AND session_id = ?";
      params.push(query.sessionId);
    }
    if (query.skillName !== undefined) {
      sql += " AND skill_name = ?";
      params.push(query.skillName);
    }
    if (query.since !== undefined) {
      sql += " AND timestamp >= ?";
      params.push(query.since);
    }
    if (query.until !== undefined) {
      sql += " AND timestamp <= ?";
      params.push(query.until);
    }

    sql += " ORDER BY timestamp DESC";

    const offset = query.offset ?? 0;
    const limit = Math.min(query.limit ?? 100, 10000);
    sql += " LIMIT ? OFFSET ?";
    params.push(limit, offset);

    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params) as SqliteRow[];

    return rows.map((row) => ({
      id: row.id,
      timestamp: row.timestamp,
      category: row.category as EventCategory,
      severity: row.severity as Severity,
      title: row.title,
      description: row.description,
      details: safeJsonParse(row.details_json, {}),
      toolName: row.tool_name ?? undefined,
      toolParams: safeJsonParse(row.tool_params_json, undefined),
      skillName: row.skill_name ?? undefined,
      sessionId: row.session_id ?? undefined,
      agentId: row.agent_id ?? undefined,
      ruleName: row.rule_name ?? undefined,
      matchedPattern: row.matched_pattern ?? undefined,
      action: row.action as "alert" | "blocked",
    }));
  }

  async getStats(since?: number): Promise<EventStats> {
    this.ensureOpen();
    await this.initialize();

    const whereClause = since !== undefined ? " WHERE timestamp >= ?" : "";
    const params: unknown[] = since !== undefined ? [since] : [];

    // Use SQL aggregation instead of loading all rows into memory
    const totalRow = this.db.prepare(
      `SELECT COUNT(*) as total,
              MIN(timestamp) as first_ts,
              MAX(timestamp) as last_ts,
              SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) as blocked_count,
              SUM(CASE WHEN action = 'alert' THEN 1 ELSE 0 END) as alert_count
       FROM events${whereClause}`
    ).get(...params) as SqliteRow;

    const bySeverity: Record<string, number> = {
      critical: 0, high: 0, medium: 0, low: 0, info: 0,
    };
    const sevRows = this.db.prepare(
      `SELECT severity, COUNT(*) as cnt FROM events${whereClause} GROUP BY severity`
    ).all(...params) as SqliteRow[];
    for (const row of sevRows) {
      bySeverity[row.severity] = row.cnt;
    }

    const byCategory: Record<string, number> = {};
    const catRows = this.db.prepare(
      `SELECT category, COUNT(*) as cnt FROM events${whereClause} GROUP BY category`
    ).all(...params) as SqliteRow[];
    for (const row of catRows) {
      byCategory[row.category] = row.cnt;
    }

    const byRule: Record<string, number> = {};
    const ruleWhereClause = since !== undefined
      ? " WHERE timestamp >= ? AND rule_name IS NOT NULL"
      : " WHERE rule_name IS NOT NULL";
    const ruleRows = this.db.prepare(
      `SELECT rule_name, COUNT(*) as cnt FROM events${ruleWhereClause} GROUP BY rule_name`
    ).all(...params) as SqliteRow[];
    for (const row of ruleRows) {
      byRule[row.rule_name] = row.cnt;
    }

    return {
      total: totalRow.total,
      bySeverity: bySeverity as Record<Severity, number>,
      byCategory,
      byRule,
      blockedCount: totalRow.blocked_count ?? 0,
      alertCount: totalRow.alert_count ?? 0,
      timeRange:
        totalRow.total > 0
          ? { first: totalRow.first_ts, last: totalRow.last_ts }
          : null,
    };
  }

  async timeSeries(
    bucketMs: number = 60_000,
    since?: number
  ): Promise<TimeSeriesBucket[]> {
    bucketMs = Math.floor(bucketMs);
    if (bucketMs <= 0) throw new Error("bucketMs must be positive");
    this.ensureOpen();
    await this.initialize();

    const whereClause = since !== undefined ? " WHERE timestamp >= ?" : "";
    const params: unknown[] = since !== undefined ? [since] : [];

    // Use SQL aggregation to bucket timestamps
    const rows = this.db.prepare(
      `SELECT (timestamp / ? * ?) as bucket_ts,
              COUNT(*) as cnt,
              SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) as blocked_cnt
       FROM events${whereClause}
       GROUP BY bucket_ts
       ORDER BY bucket_ts ASC`
    ).all(bucketMs, bucketMs, ...params) as SqliteRow[];

    return rows.map((row: SqliteRow) => ({
      timestamp: row.bucket_ts,
      count: row.cnt,
      blocked: row.blocked_cnt ?? 0,
    }));
  }

  async addSession(session: Session): Promise<void> {
    this.ensureOpen();
    await this.initialize();

    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO sessions (session_id, agent_id, started_at, ended_at, tool_call_count, event_count, skills_used_json)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      session.sessionId,
      session.agentId,
      session.startedAt,
      session.endedAt,
      session.toolCallCount,
      session.eventCount,
      session.skillsUsed ? JSON.stringify(session.skillsUsed) : null
    );
  }

  async updateSession(sessionId: string, updates: Partial<Session>): Promise<void> {
    this.ensureOpen();
    await this.initialize();

    const fields: string[] = [];
    const values: unknown[] = [];

    if (updates.agentId !== undefined) {
      fields.push("agent_id = ?");
      values.push(updates.agentId);
    }
    if (updates.endedAt !== undefined) {
      fields.push("ended_at = ?");
      values.push(updates.endedAt);
    }
    if (updates.toolCallCount !== undefined) {
      fields.push("tool_call_count = ?");
      values.push(updates.toolCallCount);
    }
    if (updates.eventCount !== undefined) {
      fields.push("event_count = ?");
      values.push(updates.eventCount);
    }
    if (updates.skillsUsed !== undefined) {
      fields.push("skills_used_json = ?");
      values.push(updates.skillsUsed ? JSON.stringify(updates.skillsUsed) : null);
    }

    if (fields.length === 0) return;

    values.push(sessionId);
    const sql = `UPDATE sessions SET ${fields.join(", ")} WHERE session_id = ?`;
    const stmt = this.db.prepare(sql);
    stmt.run(...values);
  }

  async getSession(sessionId: string): Promise<Session | null> {
    this.ensureOpen();
    await this.initialize();

    const stmt = this.db.prepare("SELECT * FROM sessions WHERE session_id = ?");
    const row = stmt.get(sessionId) as SqliteRow;

    if (!row) return null;

    return {
      sessionId: row.session_id,
      agentId: row.agent_id ?? undefined,
      startedAt: row.started_at,
      endedAt: row.ended_at ?? undefined,
      toolCallCount: row.tool_call_count,
      eventCount: row.event_count,
      skillsUsed: safeJsonParse(row.skills_used_json, undefined),
    };
  }

  async saveBaseline(baseline: SkillBaseline): Promise<void> {
    this.ensureOpen();
    await this.initialize();

    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO skill_baselines (skill_name, first_seen, last_seen, session_count, tool_usage_json, path_patterns_json, domain_patterns_json, command_patterns_json, avg_calls_per_session, std_dev_calls, max_calls_observed)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      baseline.skillName,
      baseline.firstSeen,
      baseline.lastSeen,
      baseline.sessionCount,
      baseline.toolUsage ? JSON.stringify(baseline.toolUsage) : null,
      baseline.pathPatterns ? JSON.stringify(baseline.pathPatterns) : null,
      baseline.domainPatterns ? JSON.stringify(baseline.domainPatterns) : null,
      baseline.commandPatterns ? JSON.stringify(baseline.commandPatterns) : null,
      baseline.avgCallsPerSession,
      baseline.stdDevCalls,
      baseline.maxCallsObserved
    );
  }

  async getBaseline(skillName: string): Promise<SkillBaseline | null> {
    this.ensureOpen();
    await this.initialize();

    const stmt = this.db.prepare("SELECT * FROM skill_baselines WHERE skill_name = ?");
    const row = stmt.get(skillName) as SqliteRow;

    if (!row) return null;

    return {
      skillName: row.skill_name,
      firstSeen: row.first_seen,
      lastSeen: row.last_seen,
      sessionCount: row.session_count,
      toolUsage: safeJsonParse(row.tool_usage_json, undefined),
      pathPatterns: safeJsonParse(row.path_patterns_json, undefined),
      domainPatterns: safeJsonParse(row.domain_patterns_json, undefined),
      commandPatterns: safeJsonParse(row.command_patterns_json, undefined),
      avgCallsPerSession: row.avg_calls_per_session,
      stdDevCalls: row.std_dev_calls,
      maxCallsObserved: row.max_calls_observed,
    };
  }

  async listBaselines(): Promise<SkillBaseline[]> {
    this.ensureOpen();
    await this.initialize();

    const stmt = this.db.prepare("SELECT * FROM skill_baselines ORDER BY last_seen DESC");
    const rows = stmt.all() as SqliteRow[];

    return rows.map((row: SqliteRow) => ({
      skillName: row.skill_name,
      firstSeen: row.first_seen,
      lastSeen: row.last_seen,
      sessionCount: row.session_count,
      toolUsage: safeJsonParse(row.tool_usage_json, undefined),
      pathPatterns: safeJsonParse(row.path_patterns_json, undefined),
      domainPatterns: safeJsonParse(row.domain_patterns_json, undefined),
      commandPatterns: safeJsonParse(row.command_patterns_json, undefined),
      avgCallsPerSession: row.avg_calls_per_session,
      stdDevCalls: row.std_dev_calls,
      maxCallsObserved: row.max_calls_observed,
    }));
  }

  async addDismissal(pattern: DismissalPattern): Promise<void> {
    this.ensureOpen();
    await this.initialize();

    const stmt = this.db.prepare(`
      INSERT OR REPLACE INTO dismissals (id, rule_name, tool_name, skill_name, reason, created_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      pattern.id,
      pattern.ruleName ?? null,
      pattern.toolName ?? null,
      pattern.skillName ?? null,
      pattern.reason,
      pattern.createdAt,
      pattern.expiresAt ?? null
    );
  }

  async removeDismissal(id: string): Promise<boolean> {
    this.ensureOpen();
    await this.initialize();

    const stmt = this.db.prepare("DELETE FROM dismissals WHERE id = ?");
    const result = stmt.run(id);
    return result.changes > 0;
  }

  async listDismissals(): Promise<DismissalPattern[]> {
    this.ensureOpen();
    await this.initialize();

    const now = Date.now();
    const stmt = this.db.prepare(
      "SELECT * FROM dismissals WHERE expires_at IS NULL OR expires_at >= ? ORDER BY created_at DESC"
    );
    const rows = stmt.all(now) as SqliteRow[];

    return rows.map((row: SqliteRow) => ({
      id: row.id,
      ruleName: row.rule_name ?? undefined,
      toolName: row.tool_name ?? undefined,
      skillName: row.skill_name ?? undefined,
      reason: row.reason,
      createdAt: row.created_at,
      expiresAt: row.expires_at ?? undefined,
    }));
  }

  async clearDismissals(): Promise<void> {
    this.ensureOpen();
    await this.initialize();

    this.db.exec("DELETE FROM dismissals");
  }

  async clear(): Promise<void> {
    this.ensureOpen();
    await this.initialize();

    this.db.exec("DELETE FROM events; DELETE FROM sessions; DELETE FROM skill_baselines; DELETE FROM dismissals;");
  }

  async close(): Promise<void> {
    this.closed = true;
    // Await pending initialization to prevent leaked database handles
    if (this.initPromise) {
      try { await this.initPromise; } catch { /* ignore init errors during close */ }
    }
    if (this.db && this.initialized) {
      this.db.close();
      this.db = null as unknown as SqliteDatabase; // prevent use-after-close
      this.initialized = false;
      this.initPromise = null;
      this.insertCount = 0;
    }
  }
}

// ─── 工厂函数 ────────────────────────────────────────────────────

/**
 * 创建存储后端
 * 尝试使用 SQLite，若失败则回退到内存存储
 */
export async function createStore(config: StoreConfig = {}): Promise<StorageBackend> {
  const { type = "sqlite", sqlitePath = "carapace.db", maxEvents = 10000 } = config;

  if (type === "memory") {
    return new MemoryBackend(maxEvents);
  }

  // 优先使用 SQLite
  try {
    const backend = new SqliteBackend(sqlitePath, maxEvents);
    await backend.initialize();
    return backend;
  } catch (error) {
    process.stderr.write(
      `[CARAPACE] Failed to initialize SQLite backend, falling back to memory: ${error instanceof Error ? error.message : String(error)}\n`
    );
    return new MemoryBackend(maxEvents);
  }
}
