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
    const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

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
    const config: Record<string, unknown> = {};
    if (existsSync(configPath)) {
      try {
        const parsed = JSON.parse(readFileSync(configPath, "utf-8")) as Record<string, unknown>;
        // Filter prototype pollution keys
        for (const key of Object.keys(parsed)) {
          if (key !== "__proto__" && key !== "constructor" && key !== "prototype") {
            config[key] = parsed[key];
          }
        }
      } catch {
        // Start with empty config if file is invalid
      }
    }

    if (DANGEROUS_KEYS.has(skillName) || !skillName.trim() || !/^[\w.@/-]+$/.test(skillName.trim())) {
      console.error(color(`Error: Invalid skill name: "${skillName}". Must be non-empty and contain only letters, digits, dots, hyphens, underscores, slashes, or @.`, COLORS.red));
      process.exit(1);
    }

    if (action === "trust") {
      // trustedSkills may be an array (from YAML config) or a Record (from JSON config)
      if (Array.isArray(config.trustedSkills)) {
        if (!config.trustedSkills.includes(skillName)) {
          config.trustedSkills.push(skillName);
        }
      } else {
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
      }

      console.log(
        color(
          `✓ Skill '${skillName}' marked as trusted`,
          COLORS.green
        )
      );
    } else {
      if (Array.isArray(config.trustedSkills)) {
        config.trustedSkills = config.trustedSkills.filter((s: unknown) => s !== skillName);
      } else if (config.trustedSkills && typeof config.trustedSkills === "object") {
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
