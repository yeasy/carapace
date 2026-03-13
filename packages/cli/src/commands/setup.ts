/**
 * 交互式配置向导
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { stdin as input, stdout as output } from "process";
import { createInterface, Interface } from "readline";
import { color, COLORS } from "../utils.js";

interface FrameworkConfig {
  name: string;
  adapter?: string;
  description: string;
}

interface SetupConfig {
  framework: FrameworkConfig | null;
  blockOnCritical: boolean;
  webhookUrl: string;
  enableBaseline: boolean;
  maxToolCallsPerMinute: number;
}

function detectFramework(): FrameworkConfig | null {
  const packageJsonPath = join(process.cwd(), "package.json");

  if (!existsSync(packageJsonPath)) {
    return null;
  }

  try {
    const content = readFileSync(packageJsonPath, "utf-8");
    const packageJson = JSON.parse(content);
    const deps = {
      ...packageJson.dependencies,
      ...packageJson.devDependencies,
    };

    // 检测框架
    if (deps.openclaw) {
      return {
        name: "openclaw",
        adapter: "openclaw",
        description: "OpenClaw Agent Framework",
      };
    }
    if (deps.langchain || deps["@langchain/core"]) {
      return {
        name: "langchain",
        adapter: "langchain",
        description: "LangChain Framework",
      };
    }
    if (deps.crewai) {
      return {
        name: "crewai",
        description: "CrewAI Framework",
      };
    }
    if (deps.autogen) {
      return {
        name: "autogen",
        description: "AutoGen Framework",
      };
    }
    if (deps["@modelcontextprotocol/sdk"]) {
      return {
        name: "mcp",
        adapter: "mcp",
        description: "Model Context Protocol",
      };
    }
  } catch {
    // 忽略解析错误
  }

  return null;
}

/**
 * 简单的交互式提示函数
 */
function ask(
  rl: Interface,
  question: string,
  defaultValue?: string
): Promise<string> {
  return new Promise((resolve) => {
    const prompt =
      defaultValue !== undefined
        ? `${question} [${defaultValue}]: `
        : `${question}: `;

    rl.question(prompt, (answer: string) => {
      const trimmed = answer.trim();
      resolve(trimmed || defaultValue || "");
    });
  });
}

function generateSetupConfig(config: SetupConfig): string {
  const lines: string[] = [];

  // 基础配置
  lines.push("# Carapace Configuration");
  lines.push("# AI Agent Runtime Security Monitoring");
  lines.push("");

  // 框架信息
  if (config.framework) {
    lines.push(`# Framework: ${config.framework.description}`);
    lines.push(`framework: ${config.framework.name}`);
    if (config.framework.adapter) {
      lines.push(`adapter: ${config.framework.adapter}`);
    }
  } else {
    lines.push("# Framework: auto-detection disabled");
  }

  lines.push("");

  lines.push("# Critical threat blocking");
  lines.push(`blockOnCritical: ${config.blockOnCritical}`);
  lines.push("");

  lines.push("# Alert webhook URL");
  if (config.webhookUrl) {
    lines.push(`alertWebhook: "${config.webhookUrl}"`);
  } else {
    lines.push("alertWebhook: \"\"");
  }
  lines.push("");

  lines.push("# Event logging");
  lines.push("logFile: ~/.carapace/events.jsonl");
  lines.push("");

  lines.push("# Tool call rate limiting");
  lines.push(`maxToolCallsPerMinute: ${config.maxToolCallsPerMinute}`);
  lines.push("");

  lines.push("# Behavior baseline learning");
  lines.push(`enableBaseline: ${config.enableBaseline}`);
  lines.push("");

  // 框架特定配置
  if (config.framework?.adapter === "langchain") {
    lines.push("# LangChain adapter configuration");
    lines.push("adapter:");
    lines.push("  type: langchain");
    lines.push("  captureTools: true");
    lines.push("  capturePaths: true");
  } else if (config.framework?.adapter === "openclaw") {
    lines.push("# OpenClaw adapter configuration");
    lines.push("adapter:");
    lines.push("  type: openclaw");
    lines.push("  captureTools: true");
  } else if (config.framework?.adapter === "mcp") {
    lines.push("# MCP adapter configuration");
    lines.push("adapter:");
    lines.push("  type: mcp");
    lines.push("  captureTools: true");
  }

  return lines.join("\n");
}

export async function setupCommand(): Promise<void> {
  console.log(`${color("Carapace Setup Wizard", COLORS.bright)}\n`);

  const rl = createInterface({ input, output });

  try {
    const config: SetupConfig = {
      framework: null,
      blockOnCritical: true,
      webhookUrl: "",
      enableBaseline: true,
      maxToolCallsPerMinute: 60,
    };

    // Step 1: Framework detection
    console.log(color("Step 1: Framework Detection", COLORS.cyan));
    const detectedFramework = detectFramework();

    if (detectedFramework) {
      console.log(
        `Detected: ${color(detectedFramework.description, COLORS.green)}`
      );
      const confirm = await ask(rl, "Use this framework? (y/n)", "y");
      if (confirm.toLowerCase() === "y") {
        config.framework = detectedFramework;
      }
    } else {
      console.log(
        color("No framework detected in package.json", COLORS.yellow)
      );
    }
    console.log("");

    // Step 2: Auto-blocking
    console.log(color("Step 2: Security Configuration", COLORS.cyan));
    const blockAnswer = await ask(
      rl,
      "Enable auto-blocking of critical threats? (y/n)",
      "y"
    );
    config.blockOnCritical = blockAnswer.toLowerCase() === "y";
    console.log("");

    // Step 3: Webhook alerts
    console.log(color("Step 3: Webhook Alerts", COLORS.cyan));
    const webhookAnswer = await ask(
      rl,
      "Set up webhook alerts? Paste URL or press Enter to skip",
      ""
    );
    if (webhookAnswer) {
      config.webhookUrl = webhookAnswer;
    }
    console.log("");

    // Step 4: Baseline learning
    console.log(color("Step 4: Behavior Baseline", COLORS.cyan));
    const baselineAnswer = await ask(
      rl,
      "Enable behavior baseline learning? (y/n)",
      "y"
    );
    config.enableBaseline = baselineAnswer.toLowerCase() === "y";
    console.log("");

    // Step 5: Tool call rate limit
    console.log(color("Step 5: Rate Limiting", COLORS.cyan));
    const rateAnswer = await ask(
      rl,
      "Max tool calls per minute? (default: 60)",
      "60"
    );
    const rateNum = parseInt(rateAnswer, 10);
    if (!isNaN(rateNum) && rateNum > 0) {
      config.maxToolCallsPerMinute = rateNum;
    }
    console.log("");

    // Generate and save configuration
    console.log(color("Generating configuration...", COLORS.cyan));
    const configContent = generateSetupConfig(config);

    const configPath = join(process.cwd(), ".carapace.yml");
    writeFileSync(configPath, configContent, "utf-8");
    console.log(
      `${color("✓", COLORS.green)} Configuration file created: ${color(configPath, COLORS.cyan)}`
    );

    // Create ~/.carapace directory
    const homeDir = homedir();
    const carapaceDir = join(homeDir, ".carapace");
    if (!existsSync(carapaceDir)) {
      mkdirSync(carapaceDir, { recursive: true });
      console.log(
        `${color("✓", COLORS.green)} Directory created: ${color(carapaceDir, COLORS.cyan)}`
      );
    }

    console.log("");
    console.log(color("Setup Summary:", COLORS.bright));
    console.log(
      `  ${color("Framework:", COLORS.cyan)} ${config.framework?.description || "None detected"}`
    );
    console.log(
      `  ${color("Block Critical:", COLORS.cyan)} ${config.blockOnCritical ? "Enabled" : "Disabled"}`
    );
    console.log(
      `  ${color("Webhook Alerts:", COLORS.cyan)} ${config.webhookUrl || "Disabled"}`
    );
    console.log(
      `  ${color("Behavior Baseline:", COLORS.cyan)} ${config.enableBaseline ? "Enabled" : "Disabled"}`
    );
    console.log(
      `  ${color("Max Tool Calls/min:", COLORS.cyan)} ${config.maxToolCallsPerMinute}`
    );

    console.log("");
    console.log(color("Next steps:", COLORS.bright));
    console.log(
      `  1. Review configuration: ${color("cat .carapace.yml", COLORS.cyan)}`
    );
    console.log(
      `  2. Test configuration: ${color("carapace config", COLORS.cyan)}`
    );
    console.log(`  3. Run audit: ${color("carapace scan", COLORS.cyan)}`);
  } catch (err) {
    console.error(
      color(`Error: ${err instanceof Error ? err.message : String(err)}`, COLORS.red)
    );
    process.exit(1);
  } finally {
    rl.close();
  }
}
