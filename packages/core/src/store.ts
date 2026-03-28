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

  constructor(maxEvents = 10000) {
    super();
    this.maxEvents = maxEvents;
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
    let result = this.events;

    if (query.category) result = result.filter((e) => e.category === query.category);
    if (query.severity) result = result.filter((e) => e.severity === query.severity);
    if (query.ruleName) result = result.filter((e) => e.ruleName === query.ruleName);
    if (query.sessionId) result = result.filter((e) => e.sessionId === query.sessionId);
    if (query.skillName) result = result.filter((e) => e.skillName === query.skillName);
    if (query.since) result = result.filter((e) => e.timestamp >= query.since!);
    if (query.until) result = result.filter((e) => e.timestamp <= query.until!);

    // 按时间倒序
    result = result.slice().sort((a, b) => b.timestamp - a.timestamp);

    const offset = query.offset ?? 0;
    const limit = query.limit ?? 100;
    return result.slice(offset, offset + limit);
  }

  async getStats(since?: number): Promise<EventStats> {
    const events = since ? this.events.filter((e) => e.timestamp >= since) : this.events;

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

  async timeSeries(
    bucketMs: number = 60_000,
    since?: number
  ): Promise<TimeSeriesBucket[]> {
    const events = since ? this.events.filter((e) => e.timestamp >= since) : this.events;

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
  }

  async updateSession(sessionId: string, updates: Partial<Session>): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (session) {
      this.sessions.set(sessionId, { ...session, ...updates });
    }
  }

  async getSession(sessionId: string): Promise<Session | null> {
    return this.sessions.get(sessionId) ?? null;
  }

  async saveBaseline(baseline: SkillBaseline): Promise<void> {
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
    return [...this.dismissals.values()].filter(
      (p) => !p.expiresAt || p.expiresAt >= now
    );
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

  constructor(dbPath: string = ":memory:") {
    super();
    // 延迟初始化，在实际使用时再导入 better-sqlite3
    this.dbPath = dbPath;
  }

  private dbPath: string;

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
      // Reset so next call can retry
      this.initPromise = null;
      throw new Error(
        `Failed to initialize SQLite backend: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  async addEvent(event: SecurityEvent): Promise<void> {
    await this.initialize();

    const stmt = this.db.prepare(`
      INSERT INTO events (id, timestamp, category, severity, title, description, tool_name, skill_name, session_id, agent_id, rule_name, matched_pattern, action, details_json, tool_params_json)
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
  }

  async getEventById(id: string): Promise<SecurityEvent | null> {
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
    await this.initialize();

    let sql = "SELECT * FROM events WHERE 1=1";
    const params: unknown[] = [];

    if (query.category) {
      sql += " AND category = ?";
      params.push(query.category);
    }
    if (query.severity) {
      sql += " AND severity = ?";
      params.push(query.severity);
    }
    if (query.ruleName) {
      sql += " AND rule_name = ?";
      params.push(query.ruleName);
    }
    if (query.sessionId) {
      sql += " AND session_id = ?";
      params.push(query.sessionId);
    }
    if (query.skillName) {
      sql += " AND skill_name = ?";
      params.push(query.skillName);
    }
    if (query.since) {
      sql += " AND timestamp >= ?";
      params.push(query.since);
    }
    if (query.until) {
      sql += " AND timestamp <= ?";
      params.push(query.until);
    }

    sql += " ORDER BY timestamp DESC";

    const offset = query.offset ?? 0;
    const limit = query.limit ?? 100;
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
    await this.initialize();

    const whereClause = since ? " WHERE timestamp >= ?" : "";
    const params: unknown[] = since ? [since] : [];

    // Use SQL aggregation instead of loading all rows into memory
    const totalRow = this.db.prepare(
      `SELECT COUNT(*) as total,
              MIN(timestamp) as first_ts,
              MAX(timestamp) as last_ts,
              SUM(CASE WHEN action = 'blocked' THEN 1 ELSE 0 END) as blocked_count,
              SUM(CASE WHEN action != 'blocked' THEN 1 ELSE 0 END) as alert_count
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
    const ruleWhereClause = since
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
    await this.initialize();

    const whereClause = since ? " WHERE timestamp >= ?" : "";
    const params: unknown[] = since ? [since] : [];

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
    await this.initialize();

    const stmt = this.db.prepare(`
      INSERT INTO sessions (session_id, agent_id, started_at, ended_at, tool_call_count, event_count, skills_used_json)
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
    await this.initialize();

    const stmt = this.db.prepare("DELETE FROM dismissals WHERE id = ?");
    const result = stmt.run(id);
    return result.changes > 0;
  }

  async listDismissals(): Promise<DismissalPattern[]> {
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
    await this.initialize();

    this.db.exec("DELETE FROM dismissals");
  }

  async clear(): Promise<void> {
    await this.initialize();

    this.db.exec("DELETE FROM events; DELETE FROM sessions; DELETE FROM skill_baselines; DELETE FROM dismissals;");
  }

  async close(): Promise<void> {
    if (this.db && this.initialized) {
      this.db.close();
      this.initialized = false;
      this.initPromise = null; // allow re-initialization if needed
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
    const backend = new SqliteBackend(sqlitePath);
    await backend.initialize();
    return backend;
  } catch (error) {
    process.stderr.write(
      `[CARAPACE] Failed to initialize SQLite backend, falling back to memory: ${error instanceof Error ? error.message : String(error)}\n`
    );
    return new MemoryBackend(maxEvents);
  }
}
