/**
 * 管理事件驳回 (dismissals)
 */

import { createStore, type StorageBackend } from "@carapace/core";
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

    try {
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
        const reason = typeof flags.reason === "string" ? flags.reason : "Dismissed by user";
        await dismissEvent(store, eventId, reason);
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

/**
 * 驳回单个事件 — 查找事件并创建驳回模式
 */
async function dismissEvent(store: StorageBackend, eventId: string, reason: string): Promise<void> {
  // Look up the event by ID to extract rule/tool info for the dismissal pattern
  const event = await store.getEventById(eventId);

  if (!event) {
    console.error(
      color(`Event not found: ${eventId}`, COLORS.red)
    );
    process.exit(1);
  }

  const dismissalId = `d-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  await store.addDismissal({
    id: dismissalId,
    ruleName: event.ruleName,
    toolName: event.toolName,
    skillName: event.skillName,
    reason,
    createdAt: Date.now(),
  });

  console.log(
    color(`✓ Event ${eventId} dismissed (dismissal ID: ${dismissalId})`, COLORS.green)
  );
  console.log(
    `  Rule: ${event.ruleName ?? "any"} | Tool: ${event.toolName ?? "any"} | Reason: ${reason}`
  );
}

/**
 * 列出所有已驳回的模式
 */
async function listDismissals(store: StorageBackend): Promise<void> {
  console.log(`${color("Dismissed Patterns", COLORS.bright)}\n`);

  const dismissals = await store.listDismissals();

  if (dismissals.length === 0) {
    console.log(color("No active dismissals.", COLORS.dim));
    return;
  }

  const rows = dismissals.map((d) => [
    d.id,
    d.ruleName ?? "*",
    d.toolName ?? "*",
    d.reason,
    formatRelativeTime(d.createdAt),
    d.expiresAt ? formatRelativeTime(d.expiresAt) : "never",
  ]);

  console.log(
    formatTable(
      ["ID", "Rule", "Tool", "Reason", "Created", "Expires"],
      rows
    )
  );
  console.log(`\n${color(`Total: ${dismissals.length} active dismissal(s)`, COLORS.dim)}`);
}

/**
 * 清空所有驳回模式
 */
async function clearDismissals(store: StorageBackend): Promise<void> {
  const dismissals = await store.listDismissals();
  await store.clearDismissals();
  console.log(color(`✓ Cleared ${dismissals.length} dismissal(s)`, COLORS.green));
}
