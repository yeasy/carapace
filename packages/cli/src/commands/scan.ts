/**
 * 一次性配置审计
 */

import { createStore } from "@carapace/core";
import { color, COLORS, loadConfig, getDbPath } from "../utils.js";

export async function scanCommand(): Promise<void> {
  console.log(`${color("Configuration Audit", COLORS.bright)}\n`);

  try {
    const config = loadConfig();
    const dbPath = getDbPath();

    const results: { status: string; message: string }[] = [];

    // 检查 blockOnCritical 是否启用
    if (config.blockOnCritical === true) {
      results.push({
        status: "✓",
        message: "blockOnCritical is enabled (recommended)",
      });
    } else {
      results.push({
        status: "⚠",
        message:
          "blockOnCritical is disabled. Consider enabling for critical events.",
      });
    }

    // 检查是否定义了信任技能
    if (config.trustedSkills && Object.keys(config.trustedSkills).length > 0) {
      results.push({
        status: "✓",
        message: `${Object.keys(config.trustedSkills).length} trusted skill(s) defined`,
      });
    } else {
      results.push({
        status: "ℹ",
        message: "No trusted skills defined. All skills are monitored.",
      });
    }

    // 检查数据库连接
    try {
      const store = await createStore({ sqlitePath: dbPath });
      await store.getStats();
      results.push({
        status: "✓",
        message: `Database accessible (${dbPath})`,
      });
    } catch {
      results.push({
        status: "✗",
        message: `Database not accessible (${dbPath})`,
      });
    }

    // 显示结果
    console.log(color("Scan Results:", COLORS.bright));
    for (const result of results) {
      const statusColor =
        result.status === "✓"
          ? COLORS.green
          : result.status === "✗"
            ? COLORS.red
            : result.status === "⚠"
              ? COLORS.yellow
              : COLORS.cyan;

      console.log(
        `  ${color(result.status, statusColor)} ${result.message}`
      );
    }

    // 总结
    const hasErrors = results.some((r) => r.status === "✗");
    const hasWarnings = results.some((r) => r.status === "⚠");

    console.log();
    if (hasErrors) {
      console.log(color("Status: FAILED", COLORS.red));
    } else if (hasWarnings) {
      console.log(color("Status: WARNING", COLORS.yellow));
    } else {
      console.log(color("Status: OK", COLORS.green));
    }
  } catch (err) {
    console.error(
      color(`Error: ${err instanceof Error ? err.message : String(err)}`, COLORS.red)
    );
    process.exit(1);
  }
}
