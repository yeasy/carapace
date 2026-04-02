/**
 * 列出和查询事件
 */

import { createStore, type EventQuery, type Severity, type SecurityEvent } from "@carapace/core";
import {
  color,
  COLORS,
  formatTable,
  formatRelativeTime,
  getDbPath,
  parseDuration,
  severityColor,
} from "../utils.js";

export async function eventsCommand(
  flags: Record<string, string | boolean>
): Promise<void> {
  try {
    const dbPath = getDbPath();
    const store = await createStore({ sqlitePath: dbPath });

    try {
    // 构建查询条件
    const query: EventQuery = { limit: 100 };

    if (flags.limit) {
      const n = parseInt(String(flags.limit), 10);
      if (isNaN(n) || n <= 0) {
        console.error(color("Invalid --limit value (must be a positive integer)", COLORS.red));
        process.exitCode = 1;
        return;
      }
      query.limit = n;
    }

    // 处理时间过滤
    if (flags.since) {
      const duration = parseDuration(String(flags.since));
      if (isNaN(duration)) {
        console.error(color(`Invalid --since value: "${flags.since}". Expected format like "24h", "7d", "30m"`, COLORS.red));
        process.exitCode = 1;
        return;
      }
      if (duration > 0) {
        query.since = Date.now() - duration;
      }
    }

    // 处理严重程度过滤
    const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
    if (flags.severity) {
      const sev = String(flags.severity).toLowerCase();
      if (!VALID_SEVERITIES.has(sev)) {
        console.error(color(`Invalid severity: ${flags.severity}. Must be one of: critical, high, medium, low, info`, COLORS.red));
        process.exitCode = 1;
        return;
      }
      query.severity = sev as Severity;
    }

    // 处理技能过滤
    if (flags.skill) {
      query.skillName = String(flags.skill);
    }

    // 处理规则过滤
    if (flags.rule) {
      query.ruleName = String(flags.rule);
    }

    // 获取事件
    const events = await store.queryEvents(query);

    // 处理导出
    if (flags.export === "csv") {
      exportCsv(events);
      return;
    }

    // 显示事件表格
    if (events.length === 0) {
      console.log("No events found.");
      return;
    }

    console.log(
      `${color(`Security Events (showing ${events.length})`, COLORS.bright)}\n`
    );

    const rows = events.map((evt) => {
      return [
        color(evt.severity || "info", severityColor(evt.severity || "info")),
        evt.ruleName || "unknown",
        evt.skillName || "-",
        formatRelativeTime(evt.timestamp),
      ];
    });

    console.log(formatTable(["Severity", "Rule", "Skill", "Time"], rows));

    // 显示详细信息选项
    if (events.length > 0) {
      console.log(
        `\n${color("Tip:", COLORS.cyan)} Use 'carapace events --export csv' to export events`
      );
    }
    } finally {
      await store.close();
    }
  } catch (err) {
    console.error(
      color(`Error: ${err instanceof Error ? err.message : String(err)}`, COLORS.red)
    );
    process.exitCode = 1;
  }
}

/**
 * Sanitize a CSV cell value to prevent formula injection.
 * Prefixes dangerous leading characters with a single quote.
 */
function csvSafe(value: string): string {
  // Normalize newlines before escaping
  const normalized = value.replace(/\r\n/g, " ").replace(/\r/g, " ").replace(/\n/g, " ");
  const escaped = normalized.replace(/"/g, '""');
  // Prevent CSV formula injection
  if (/^[=+\-@\t\r]/.test(escaped)) {
    return `"'${escaped}"`;
  }
  return `"${escaped}"`;
}

function exportCsv(events: SecurityEvent[]): void {
  // CSV 标题
  console.log("timestamp,severity,action,rule,skill,tool,category,message");

  // CSV 行
  for (const evt of events) {
    const timestamp = new Date(evt.timestamp).toISOString();
    const severity = evt.severity || "info";
    const action = evt.action || "alert";
    const rule = evt.ruleName || "";
    const skill = evt.skillName || "";
    const tool = evt.toolName || "";
    const category = evt.category || "";
    const message = evt.description || "";

    console.log(
      `${csvSafe(timestamp)},${csvSafe(severity)},${csvSafe(action)},${csvSafe(rule)},${csvSafe(skill)},${csvSafe(tool)},${csvSafe(category)},${csvSafe(message)}`
    );
  }
}
