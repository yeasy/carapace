/**
 * 存储后端 — 支持内存和 SQLite 持久化
 */

import type { SecurityEvent, Severity, EventCategory } from "./types.js";

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

  abstract clear(): Promise<void>;
  abstract close(): Promise<void>;
}

// ─── 内存后端 ────────────────────────────────────────────────────

export class MemoryBackend extends StorageBackend {
  private events: SecurityEvent[] = [];
  private sessions: Map<string, Session> = new Map();
  private baselines: Map<string, SkillBaseline> = new Map();
  private maxEvents: number;

  constructor(maxEvents = 10000) {
    super();
    this.maxEvents = maxEvents;
  }

  async addEvent(event: SecurityEvent): Promise<void> {
    this.events.push(event);
    // 超过上限时淘汰最旧的事件
    if (this.events.length > this.maxEvents) {
      this.events = this.events.slice(-this.maxEvents);
    }
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

    for (const e of events) {
      bySeverity[e.severity] = (bySeverity[e.severity] ?? 0) + 1;
      byCategory[e.category] = (byCategory[e.category] ?? 0) + 1;
      if (e.ruleName) byRule[e.ruleName] = (byRule[e.ruleName] ?? 0) + 1;
      if (e.action === "blocked") blockedCount++;
      else alertCount++;
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
          ? {
              first: events.reduce(
                (min, e) => (e.timestamp < min ? e.timestamp : min),
                events[0].timestamp
              ),
              last: events.reduce(
                (max, e) => (e.timestamp > max ? e.timestamp : max),
                events[0].timestamp
              ),
            }
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

  async clear(): Promise<void> {
    this.events = [];
    this.sessions.clear();
    this.baselines.clear();
  }

  async close(): Promise<void> {
    // 内存后端无需清理
  }
}

// ─── SQLite 后端 ─────────────────────────────────────────────────

export class SqliteBackend extends StorageBackend {
  private db: any;
  private initialized = false;

  constructor(dbPath: string = ":memory:") {
    super();
    // 延迟初始化，在实际使用时再导入 better-sqlite3
    this.dbPath = dbPath;
  }

  private dbPath: string;

  async initialize(): Promise<void> {
    if (this.initialized) return;

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
          action TEXT NOT NULL,
          details_json TEXT,
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
      `);

      this.initialized = true;
    } catch (error) {
      throw new Error(
        `Failed to initialize SQLite backend: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  async addEvent(event: SecurityEvent): Promise<void> {
    await this.initialize();

    const stmt = this.db.prepare(`
      INSERT INTO events (id, timestamp, category, severity, title, description, tool_name, skill_name, session_id, agent_id, rule_name, action, details_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
      event.action,
      JSON.stringify(event.details)
    );
  }

  async queryEvents(query: EventQuery = {}): Promise<SecurityEvent[]> {
    await this.initialize();

    let sql = "SELECT * FROM events WHERE 1=1";
    const params: any[] = [];

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
    const rows = stmt.all(...params) as any[];

    return rows.map((row) => ({
      id: row.id,
      timestamp: row.timestamp,
      category: row.category as EventCategory,
      severity: row.severity as Severity,
      title: row.title,
      description: row.description,
      details: JSON.parse(row.details_json || "{}"),
      toolName: row.tool_name,
      skillName: row.skill_name,
      sessionId: row.session_id,
      agentId: row.agent_id,
      ruleName: row.rule_name,
      action: row.action as "alert" | "blocked",
    }));
  }

  async getStats(since?: number): Promise<EventStats> {
    await this.initialize();

    let sql = "SELECT * FROM events WHERE 1=1";
    const params: any[] = [];

    if (since) {
      sql += " AND timestamp >= ?";
      params.push(since);
    }

    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params) as any[];

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

    for (const row of rows) {
      bySeverity[row.severity] = (bySeverity[row.severity] ?? 0) + 1;
      byCategory[row.category] = (byCategory[row.category] ?? 0) + 1;
      if (row.rule_name) byRule[row.rule_name] = (byRule[row.rule_name] ?? 0) + 1;
      if (row.action === "blocked") blockedCount++;
      else alertCount++;
    }

    return {
      total: rows.length,
      bySeverity: bySeverity as Record<Severity, number>,
      byCategory,
      byRule,
      blockedCount,
      alertCount,
      timeRange:
        rows.length > 0
          ? {
              first: rows.reduce(
                (min, row) => (row.timestamp < min ? row.timestamp : min),
                rows[0].timestamp
              ),
              last: rows.reduce(
                (max, row) => (row.timestamp > max ? row.timestamp : max),
                rows[0].timestamp
              ),
            }
          : null,
    };
  }

  async timeSeries(
    bucketMs: number = 60_000,
    since?: number
  ): Promise<TimeSeriesBucket[]> {
    await this.initialize();

    let sql = "SELECT timestamp, action FROM events WHERE 1=1";
    const params: any[] = [];

    if (since) {
      sql += " AND timestamp >= ?";
      params.push(since);
    }

    const stmt = this.db.prepare(sql);
    const rows = stmt.all(...params) as any[];

    if (rows.length === 0) return [];

    const buckets = new Map<number, { count: number; blocked: number }>();

    for (const row of rows) {
      const key = Math.floor(row.timestamp / bucketMs) * bucketMs;
      const bucket = buckets.get(key) ?? { count: 0, blocked: 0 };
      bucket.count++;
      if (row.action === "blocked") bucket.blocked++;
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
    const values: any[] = [];

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
    const row = stmt.get(sessionId) as any;

    if (!row) return null;

    return {
      sessionId: row.session_id,
      agentId: row.agent_id,
      startedAt: row.started_at,
      endedAt: row.ended_at,
      toolCallCount: row.tool_call_count,
      eventCount: row.event_count,
      skillsUsed: row.skills_used_json ? JSON.parse(row.skills_used_json) : undefined,
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
    const row = stmt.get(skillName) as any;

    if (!row) return null;

    return {
      skillName: row.skill_name,
      firstSeen: row.first_seen,
      lastSeen: row.last_seen,
      sessionCount: row.session_count,
      toolUsage: row.tool_usage_json ? JSON.parse(row.tool_usage_json) : undefined,
      pathPatterns: row.path_patterns_json ? JSON.parse(row.path_patterns_json) : undefined,
      domainPatterns: row.domain_patterns_json ? JSON.parse(row.domain_patterns_json) : undefined,
      commandPatterns: row.command_patterns_json ? JSON.parse(row.command_patterns_json) : undefined,
      avgCallsPerSession: row.avg_calls_per_session,
      stdDevCalls: row.std_dev_calls,
      maxCallsObserved: row.max_calls_observed,
    };
  }

  async clear(): Promise<void> {
    await this.initialize();

    this.db.exec("DELETE FROM events; DELETE FROM sessions; DELETE FROM skill_baselines;");
  }

  async close(): Promise<void> {
    if (this.db && this.initialized) {
      this.db.close();
      this.initialized = false;
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
    console.warn(
      `Failed to initialize SQLite backend, falling back to memory: ${error instanceof Error ? error.message : String(error)}`
    );
    return new MemoryBackend(maxEvents);
  }
}
