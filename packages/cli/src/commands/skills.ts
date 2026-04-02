/**
 * 管理技能和信任分数
 */

import { createStore, type StorageBackend } from "@carapace/core";
import {
  color,
  COLORS,
  formatTable,
  getDbPath,
} from "../utils.js";

export async function skillsCommand(
  args: string[],
  _flags: Record<string, string | boolean>
): Promise<void> {
  try {
    const dbPath = getDbPath();
    const store = await createStore({ sqlitePath: dbPath });

    try {
      if (args.length > 0 && args[0] === "inspect") {
        await inspectSkill(store, args[1]);
      } else {
        await listSkills(store);
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
 * 列出所有技能
 */
async function listSkills(store: StorageBackend): Promise<void> {
  console.log(`${color("Skills and Trust Scores", COLORS.bright)}\n`);

  // 查询所有事件，单遍聚合技能信息
  const allEvents = await store.queryEvents({ limit: 10000 });
  const skillMap = new Map<string, { tools: Set<string>; count: number }>();

  for (const evt of allEvents) {
    if (!evt.skillName) continue;
    let entry = skillMap.get(evt.skillName);
    if (!entry) {
      entry = { tools: new Set(), count: 0 };
      skillMap.set(evt.skillName, entry);
    }
    entry.count++;
    if (evt.toolName) entry.tools.add(evt.toolName);
  }

  if (skillMap.size === 0) {
    console.log("No skills observed yet.");
    return;
  }

  const rows: (string | number)[][] = [];
  for (const [skillName, { tools, count }] of skillMap) {
    rows.push([skillName, tools.size, count]);
  }

  rows.sort((a, b) => Number(b[2]) - Number(a[2]));

  console.log(
    formatTable(["Skill Name", "Tools", "Events"], rows)
  );
}

/**
 * 检查技能详情
 */
async function inspectSkill(store: StorageBackend, skillName: string): Promise<void> {
  if (!skillName) {
    console.error(
      color("Error: Skill name required. Usage: carapace skills inspect <name>", COLORS.red)
    );
    process.exitCode = 1;
    return;
  }

  console.log(`${color(`Skill: ${skillName}`, COLORS.bright)}\n`);

  try {
    const baseline = await store.getBaseline(skillName);

    if (!baseline) {
      console.log("Skill not found in baseline data.");
      return;
    }

    console.log(
      `${color("Profile:", COLORS.cyan)}`
    );
    console.log(`  First Seen: ${new Date(baseline.firstSeen).toISOString()}`);
    console.log(`  Last Seen: ${new Date(baseline.lastSeen).toISOString()}`);
    console.log(`  Session Count: ${baseline.sessionCount}`);
    console.log(`  Avg Calls/Session: ${baseline.avgCallsPerSession.toFixed(2)}`);

    if (baseline.toolUsage && Object.keys(baseline.toolUsage).length > 0) {
      console.log(`\n${color("Tool Usage:", COLORS.cyan)}`);
      const rows: (string | number)[][] = Object.entries(baseline.toolUsage)
        .sort((a, b) => Number(b[1]) - Number(a[1]))
        .map(([tool, count]) => [tool, count as number]);
      console.log(formatTable(["Tool", "Count"], rows));
    }

    if (baseline.pathPatterns && baseline.pathPatterns.length > 0) {
      console.log(`\n${color("File Paths:", COLORS.cyan)}`);
      baseline.pathPatterns.slice(0, 5).forEach((p: string) => {
        console.log(`  - ${p}`);
      });
      if (baseline.pathPatterns.length > 5) {
        console.log(`  ... and ${baseline.pathPatterns.length - 5} more`);
      }
    }
  } catch (err) {
    console.error(
      color(`Failed to load baseline: ${err instanceof Error ? err.message : String(err)}`, COLORS.red)
    );
    process.exitCode = 1;
  }
}
