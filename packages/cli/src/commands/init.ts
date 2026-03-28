/**
 * 初始化 Carapace 配置文件
 */

import { existsSync, writeFileSync, mkdirSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { color, COLORS, detectFramework, type FrameworkConfig } from "../utils.js";

function generateDefaultConfig(framework: FrameworkConfig | null): string {
  const lines: string[] = [];

  // 基础配置
  lines.push("# Carapace Configuration");
  lines.push("# AI Agent Runtime Security Monitoring");
  lines.push("");

  // 框架信息
  if (framework) {
    lines.push(`# Detected Framework: ${framework.description}`);
    lines.push(`framework: ${framework.name}`);
    if (framework.adapter) {
      lines.push(`adapter: ${framework.adapter}`);
    }
  } else {
    lines.push("# Framework auto-detection disabled - no framework detected");
    lines.push("# Uncomment and set the framework below:");
    lines.push("# framework: langchain");
    lines.push("# framework: openclaw");
    lines.push("# framework: crewai");
    lines.push("# framework: autogen");
    lines.push("# framework: mcp");
  }

  lines.push("");
  lines.push("# Critical threat blocking");
  lines.push("blockOnCritical: true");
  lines.push("");

  lines.push("# Alert webhook URL (optional)");
  lines.push("alertWebhook: \"\"");
  lines.push("");

  lines.push("# Event logging");
  lines.push(`logFile: ~/.carapace/events.jsonl`);
  lines.push("");

  lines.push("# Tool call rate limiting");
  lines.push("maxToolCallsPerMinute: 60");
  lines.push("");

  lines.push("# Behavior baseline learning");
  lines.push("enableBaseline: true");
  lines.push("");

  // 框架特定配置
  if (framework?.adapter === "langchain") {
    lines.push("# LangChain adapter configuration");
    lines.push("adapter:");
    lines.push("  type: langchain");
    lines.push("  captureTools: true");
    lines.push("  capturePaths: true");
  } else if (framework?.adapter === "openclaw") {
    lines.push("# OpenClaw adapter configuration");
    lines.push("adapter:");
    lines.push("  type: openclaw");
    lines.push("  captureTools: true");
  } else if (framework?.adapter === "mcp") {
    lines.push("# MCP adapter configuration");
    lines.push("adapter:");
    lines.push("  type: mcp");
    lines.push("  captureTools: true");
  }

  lines.push("");
  lines.push("# Trusted skills (optional)");
  lines.push("# trustedSkills:");
  lines.push("#   my-safe-skill: true");
  lines.push("#   another-skill:");
  lines.push("#     tool: \"*\"");
  lines.push("#     path: \"/safe/path\"");

  return lines.join("\n");
}

export async function initCommand(flags: Record<string, string | boolean> = {}): Promise<void> {
  console.log(`${color("Carapace Init", COLORS.bright)}\n`);

  try {
    const configPath = join(process.cwd(), ".carapace.yml");
    const homeDir = homedir();
    const carapaceDir = join(homeDir, ".carapace");

    // 检查配置文件是否已存在
    if (existsSync(configPath) && !flags.force) {
      console.log(
        color(`Configuration file already exists: ${configPath}`, COLORS.yellow)
      );
      console.log("Use --force to overwrite, or remove the existing file manually.");
      process.exit(0);
    }

    // 检测框架
    console.log("Detecting framework...");
    const framework = detectFramework();

    if (framework) {
      console.log(
        `  ${color("✓", COLORS.green)} Detected: ${framework.description}`
      );
    } else {
      console.log(
        `  ${color("ℹ", COLORS.cyan)} No framework detected in package.json`
      );
    }
    console.log("");

    // 生成默认配置
    const configContent = generateDefaultConfig(framework);

    // 写入配置文件
    writeFileSync(configPath, configContent, "utf-8");
    console.log(
      `${color("✓", COLORS.green)} Configuration file created: ${color(configPath, COLORS.cyan)}`
    );

    // 创建 ~/.carapace 目录
    if (!existsSync(carapaceDir)) {
      mkdirSync(carapaceDir, { recursive: true });
      console.log(
        `${color("✓", COLORS.green)} Directory created: ${color(carapaceDir, COLORS.cyan)}`
      );
    }

    console.log("");
    console.log(color("Next steps:", COLORS.bright));
    console.log(`  1. Review and customize: ${color(configPath, COLORS.cyan)}`);
    console.log(
      `  2. Test configuration: ${color("carapace config", COLORS.cyan)}`
    );
    console.log(
      `  3. Run audit: ${color("carapace scan", COLORS.cyan)}`
    );
    console.log("");
    console.log(
      color("For interactive setup, run: ", COLORS.dim) +
        color("carapace setup", COLORS.cyan)
    );
  } catch (err) {
    console.error(
      color(`Error: ${err instanceof Error ? err.message : String(err)}`, COLORS.red)
    );
    process.exit(1);
  }
}
