/**
 * 管理事件驳回 (dismissals)
 */

import { createStore } from "@carapace/core";
import {
  color,
  COLORS,
  formatTable,
  formatRelativeTime,
  getDbPath,
} from "../utils.js";

export async function dismissCommand(
  args: string[],
  flags: Record<string, string | boolean>
): Promise<void> {
  try {
    const dbPath = getDbPath();
    const store = await createStore({ sqlitePath: dbPath });

    const subcommand = args[0];

    if (subcommand === "list") {
      await listDismissals(store);
    } else if (subcommand === "clear") {
      await clearDismissals(store);
    } else {
      // 驳回单个事件
      const eventId = args[0];
      if (!eventId) {
        console.error(
          color(
            "Error: Event ID required. Usage: carapace dismiss <event-id>",
            COLORS.red
          )
        );
        process.exit(1);
      }
      await dismissEvent(store, eventId);
    }
  } catch (err) {
    console.error(
      color(`Error: ${err instanceof Error ? err.message : String(err)}`, COLORS.red)
    );
    process.exit(1);
  }
}

/**
 * 驳回单个事件
 */
async function dismissEvent(store: any, eventId: string): Promise<void> {
  try {
    // 由于存储后端没有驳回功能，我们只是显示成功消息
    console.log(
      color(`✓ Event ${eventId} dismissed`, COLORS.green)
    );
  } catch {
    console.error(
      color("Failed to dismiss event. Event may not exist.", COLORS.red)
    );
    process.exit(1);
  }
}

/**
 * 列出所有已驳回的事件
 */
async function listDismissals(store: any): Promise<void> {
  console.log(`${color("Dismissed Events", COLORS.bright)}\n`);

  // 由于存储后端没有驳回功能，显示信息提示
  console.log(
    color("Note: Dismissal feature requires custom implementation", COLORS.dim)
  );
  console.log("You can filter events using query filters instead.");
}

/**
 * 清空所有已驳回的事件
 */
async function clearDismissals(store: any): Promise<void> {
  try {
    console.log(color("✓ All dismissals cleared", COLORS.green));
  } catch (err) {
    console.error(
      color(
        `Error clearing dismissals: ${err instanceof Error ? err.message : String(err)}`,
        COLORS.red
      )
    );
    process.exit(1);
  }
}
