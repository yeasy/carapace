/**
 * 显示 Carapace 状态
 */

import { readFileSync } from "node:fs";
import { createStore } from "@carapace/core";
import { color, COLORS, formatTable, getDbPath } from "../utils.js";

const VERSION = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf-8")).version;

export async function statusCommand(): Promise<void> {
  console.log(`${color("Carapace Status", COLORS.bright)}\n`);

  try {
    const dbPath = getDbPath();
    const store = await createStore({ sqlitePath: dbPath });

    try {
    // 获取统计信息
    const stats = await store.getStats();

    console.log(
      `${color("Version:", COLORS.cyan)} ${VERSION}`
    );
    console.log(
      `${color("Storage Backend:", COLORS.cyan)} SQLite`
    );
    console.log(
      `${color("Database Path:", COLORS.cyan)} ${dbPath}`
    );
    console.log();

    // 显示配置（通过统计信息显示）
    console.log(color("Configuration:", COLORS.bright));
    console.log(
      `  Total Events: ${stats.total}`
    );
    console.log(
      `  Blocked Count: ${stats.blockedCount}`
    );
    console.log(
      `  Alert Count: ${stats.alertCount}`
    );
    console.log();

    // 显示事件统计
    console.log(color("Events by Severity:", COLORS.bright));
    const severityData = Object.entries(stats.bySeverity);
    if (severityData.length > 0) {
      const rows: (string | number)[][] = severityData.map(([sev, count]) => [
        sev,
        count,
      ]);
      console.log(formatTable(["Severity", "Count"], rows));
    } else {
      console.log("  No events recorded");
    }
    console.log();

    // 显示最近的会话
    const recentEvent = await store.queryEvents({ limit: 1 });
    if (recentEvent.length > 0) {
      const session = recentEvent[0];
      console.log(
        color(`Recent Event: ${session.id}`, COLORS.bright)
      );
      console.log(`  Time: ${new Date(session.timestamp).toISOString()}`);
      console.log(`  Category: ${session.category}`);
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
