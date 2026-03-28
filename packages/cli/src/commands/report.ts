/**
 * 生成会话报告
 */

import { createStore, type SecurityEvent } from "@carapace/core";
import {
  color,
  COLORS,
  formatTable,
  formatTime,
  getDbPath,
} from "../utils.js";

export async function reportCommand(args: string[]): Promise<void> {
  const sessionId = args[0];

  if (!sessionId) {
    console.error(
      color(
        "Error: Session ID required. Usage: carapace report <session-id>",
        COLORS.red
      )
    );
    process.exit(1);
  }

  try {
    const dbPath = getDbPath();
    const store = await createStore({ sqlitePath: dbPath });

    try {
    // 获取会话
    const session = await store.getSession(sessionId);

    if (!session) {
      console.error(
        color(`Session not found: ${sessionId}`, COLORS.red)
      );
      process.exit(1);
    }

    console.log(`${color(`Session Report: ${sessionId}`, COLORS.bright)}\n`);

    // 基本信息
    console.log(color("Session Details:", COLORS.cyan));
    console.log(`  Start: ${formatTime(session.startedAt)}`);
    if (session.endedAt) {
      console.log(`  End: ${formatTime(session.endedAt)}`);
      const duration = session.endedAt - session.startedAt;
      console.log(`  Duration: ${(duration / 1000).toFixed(1)}s`);
    }
    console.log(`  Tool Calls: ${session.toolCallCount}`);
    console.log(`  Events: ${session.eventCount}`);
    if (session.skillsUsed && session.skillsUsed.length > 0) {
      console.log(`  Skills: ${session.skillsUsed.join(", ")}`);
    }
    console.log();

    // 该会话的事件
    const events = await store.queryEvents({
      sessionId: sessionId,
      limit: 10000,
    });

    // 按严重程度分组
    const bySeverity: Record<string, number> = {};
    const byRule: Record<string, number> = {};

    for (const evt of events) {
      const severity = evt.severity || "info";
      bySeverity[severity] = (bySeverity[severity] || 0) + 1;

      const rule = evt.ruleName || "unknown";
      byRule[rule] = (byRule[rule] || 0) + 1;
    }

    // 显示严重程度统计
    console.log(color("Events by Severity:", COLORS.cyan));
    if (Object.keys(bySeverity).length > 0) {
      const rows = Object.entries(bySeverity).map(([sev, count]) => [
        sev,
        count,
      ]);
      console.log(formatTable(["Severity", "Count"], rows));
    } else {
      console.log("  No events");
    }
    console.log();

    // 显示规则统计
    if (Object.keys(byRule).length > 0) {
      console.log(color("Events by Rule:", COLORS.cyan));
      const rows = Object.entries(byRule)
        .sort((a, b) => Number(b[1]) - Number(a[1]))
        .slice(0, 10)
        .map(([rule, count]) => [rule, count]);
      console.log(formatTable(["Rule", "Count"], rows));
      console.log();
    }

    // 最近的事件时间线
    if (events.length > 0) {
      console.log(color("Recent Events:", COLORS.cyan));
      const recentEvents = events.slice(0, 5);
      const rows = recentEvents.map((evt: SecurityEvent) => [
        formatTime(evt.timestamp),
        evt.severity || "info",
        evt.ruleName || "unknown",
      ]);
      console.log(formatTable(["Time", "Severity", "Rule"], rows));

      if (events.length > 5) {
        console.log(`\n  ... and ${events.length - 5} more events`);
      }
    }
    } finally {
      await store.close();
    }
  } catch (err) {
    console.error(
      color(`Error: ${err instanceof Error ? err.message : String(err)}`, COLORS.red)
    );
    process.exit(1);
  }
}
