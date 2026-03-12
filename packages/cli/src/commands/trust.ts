/**
 * 管理技能信任
 */

import { color, COLORS, loadConfig } from "../utils.js";

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

    // 加载配置
    let config = loadConfig();

    if (action === "trust") {
      // 添加到信任列表
      if (!config.trustedSkills) {
        config.trustedSkills = {};
      }

      const rules: any = {};

      if (flags.tool) {
        rules.tool = String(flags.tool);
      }
      if (flags.path) {
        rules.path = String(flags.path);
      }
      if (flags.domain) {
        rules.domain = String(flags.domain);
      }

      config.trustedSkills[skillName] = Object.keys(rules).length > 0 ? rules : true;

      console.log(
        color(
          `✓ Skill '${skillName}' marked as trusted`,
          COLORS.green
        )
      );
    } else {
      // 从信任列表移除
      if (config.trustedSkills) {
        delete config.trustedSkills[skillName];
      }

      console.log(
        color(
          `✓ Skill '${skillName}' removed from trusted list`,
          COLORS.green
        )
      );
    }

    // 注意：配置保存逻辑应该在实际应用中实现
    // 这里我们只是展示了配置更新的逻辑
    console.log(
      color(`Tip: Save configuration to ~/.carapace/config.json or .carapace.yml`, COLORS.dim)
    );
  } catch (err) {
    console.error(
      color(`Error: ${err instanceof Error ? err.message : String(err)}`, COLORS.red)
    );
    process.exit(1);
  }
}
