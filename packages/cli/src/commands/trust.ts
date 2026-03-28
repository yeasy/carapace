/**
 * 管理技能信任
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { homedir } from "node:os";
import { color, COLORS } from "../utils.js";

export async function trustCommand(
  args: string[],
  action: "trust" | "untrust",
  flags: Record<string, string | boolean>
): Promise<void> {
  try {
    const skillName = args[0];

    if (!skillName) {
      console.error(
        color(
          `Error: Skill name required. Usage: carapace ${action} <skill>`,
          COLORS.red
        )
      );
      process.exit(1);
    }

    // Load existing config from ~/.carapace/config.json
    const configPath = join(homedir(), ".carapace", "config.json");
    let config: Record<string, unknown> = {};
    if (existsSync(configPath)) {
      try {
        config = JSON.parse(readFileSync(configPath, "utf-8"));
      } catch {
        // Start with empty config if file is invalid
      }
    }

    if (action === "trust") {
      const trusted = (config.trustedSkills as Record<string, unknown>) ?? {};
      config.trustedSkills = trusted;

      const rules: Record<string, string> = {};

      if (flags.tool) {
        rules.tool = String(flags.tool);
      }
      if (flags.path) {
        rules.path = String(flags.path);
      }
      if (flags.domain) {
        rules.domain = String(flags.domain);
      }

      trusted[skillName] = Object.keys(rules).length > 0 ? rules : true;

      console.log(
        color(
          `✓ Skill '${skillName}' marked as trusted`,
          COLORS.green
        )
      );
    } else {
      if (config.trustedSkills && typeof config.trustedSkills === "object") {
        delete (config.trustedSkills as Record<string, unknown>)[skillName];
      }

      console.log(
        color(
          `✓ Skill '${skillName}' removed from trusted list`,
          COLORS.green
        )
      );
    }

    // Persist to ~/.carapace/config.json
    const configDir = dirname(configPath);
    if (!existsSync(configDir)) {
      mkdirSync(configDir, { recursive: true });
    }
    writeFileSync(configPath, JSON.stringify(config, null, 2) + "\n");
    console.log(
      color(`  Saved to ${configPath}`, COLORS.dim)
    );
  } catch (err) {
    console.error(
      color(`Error: ${err instanceof Error ? err.message : String(err)}`, COLORS.red)
    );
    process.exit(1);
  }
}
