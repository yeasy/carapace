/**
 * 基准管理
 */

import { createStore } from "@carapace/core";
import { color, COLORS, getDbPath } from "../utils.js";

export async function baselineCommand(args: string[]): Promise<void> {
  try {
    const subcommand = args[0];
    const skillName = args[1];

    if (subcommand !== "reset") {
      console.error(
        color(
          "Error: Usage: carapace baseline reset <skill>",
          COLORS.red
        )
      );
      process.exit(1);
    }

    if (!skillName) {
      console.error(
        color(
          "Error: Skill name required. Usage: carapace baseline reset <skill>",
          COLORS.red
        )
      );
      process.exit(1);
    }

    const dbPath = getDbPath();
    const store = await createStore({ sqlitePath: dbPath });

    try {
      // 重置基准 - 清除该技能的基准数据
      const emptyBaseline = {
        skillName: skillName,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        sessionCount: 0,
        toolUsage: {},
        pathPatterns: [],
        domainPatterns: [],
        commandPatterns: [],
        avgCallsPerSession: 0,
        stdDevCalls: 0,
        maxCallsObserved: 0,
      };

      await store.saveBaseline(emptyBaseline);

      console.log(
        color(
          `✓ Baseline reset for skill '${skillName}'`,
          COLORS.green
        )
      );
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
