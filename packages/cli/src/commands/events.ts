/**
 * 列出和查询事件
 */

import { createStore, EventQuery } from "@carapace/core";
import {
  color,
  COLORS,
  formatTable,
  formatTime,
  formatRelativeTime,
  getDbPath,
  parseDuration,
} from "../utils.js";

export async function eventsCommand(
  flags: Record<string, string | boolean>
): Promise<void> {
  try {
    const dbPath = getDbPath();
    const store = await createStore({ sqlitePath: dbPath });

    // 构建查询条件
    const query: EventQuery = {
      limit: flags.limit ? parseInt(String(flags.limit), 10) : 100,
    };

    // 处理时间过滤
    if (flags.since) {
      const duration = parseDuration(String(flags.since));
      if (duration > 0) {
        query.since = Date.now() - duration;
      }
    }

    // 处理严重程度过滤
    if (flags.severity) {
      const sev = String(flags.severity) as any;
      query.severity = sev;
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
      const severityColor =
        evt.severity === "critical"
          ? COLORS.red
          : evt.severity === "high"
            ? COLORS.yellow
            : COLORS.dim;

      return [
        color(evt.severity || "info", severityColor),
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
  } catch (err) {
    console.error(
      color(`Error: ${err instanceof Error ? err.message : String(err)}`, COLORS.red)
    );
    process.exit(1);
  }
}

/**
 * 导出事件为 CSV
 */
function exportCsv(events: any[]): void {
  // CSV 标题
  console.log("timestamp,severity,rule,skill,tool,category,message");

  // CSV 行
  for (const evt of events) {
    const timestamp = new Date(evt.timestamp).toISOString();
    const severity = evt.severity || "info";
    const rule = evt.ruleName || "";
    const skill = evt.skillName || "";
    const tool = evt.toolName || "";
    const category = evt.category || "";
    const message = (evt.description || "").replace(/"/g, '""');

    console.log(
      `"${timestamp}","${severity}","${rule}","${skill}","${tool}","${category}","${message}"`
    );
  }
}
