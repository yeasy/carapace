/**
 * 显示有效配置
 */

import { color, COLORS, loadConfig } from "../utils.js";

export function configCommand(): void {
  console.log(`${color("Carapace Configuration", COLORS.bright)}\n`);

  try {
    const config = loadConfig();

    if (Object.keys(config).length === 0) {
      console.log("No configuration found.");
      console.log(
        `  Check: ~/.carapace/config.json or .carapace.yml in current directory`
      );
      return;
    }

    // 显示配置为 JSON
    console.log(JSON.stringify(config, null, 2));
  } catch (err) {
    console.error(
      color(`Error: ${err instanceof Error ? err.message : String(err)}`, COLORS.red)
    );
    process.exit(1);
  }
}
