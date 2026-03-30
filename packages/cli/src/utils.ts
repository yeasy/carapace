/**
 * CLI 工具函数
 */

import { existsSync, readFileSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { parseSimpleYaml } from "@carapace/core";

/**
 * 解析命令行参数
 * 返回 { command, args, flags }
 */
export function parseArgs(argv: string[]): {
  command: string | null;
  args: string[];
  flags: Record<string, string | boolean>;
} {
  const [, , command, ...rest] = argv;
  const args: string[] = [];
  const flags: Record<string, string | boolean> = Object.create(null);

  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i];
    if (arg.startsWith("--")) {
      const raw = arg.slice(2);
      const eqIdx = raw.indexOf("=");
      if (eqIdx !== -1) {
        flags[raw.slice(0, eqIdx)] = raw.slice(eqIdx + 1);
      } else {
        const key = raw;
        const nextArg = rest[i + 1];
        if (nextArg && !nextArg.startsWith("--")) {
          flags[key] = nextArg;
          i++;
        } else {
          flags[key] = true;
        }
      }
    } else if (arg.startsWith("-")) {
      const key = arg.slice(1);
      const nextArg = rest[i + 1];
      if (nextArg && (!nextArg.startsWith("-") || /^-\d/.test(nextArg))) {
        flags[key] = nextArg;
        i++;
      } else {
        flags[key] = true;
      }
    } else {
      args.push(arg);
    }
  }

  return { command: command || null, args, flags };
}

/**
 * 将字符串持续时间转换为毫秒
 * 支持: "24h", "7d", "30m", "1000ms"
 */
export function parseDuration(str: string): number {
  const match = str.match(/^(\d+)([a-z]+)$/i);
  if (!match) return NaN;

  const num = parseInt(match[1], 10);
  const unit = match[2].toLowerCase();

  switch (unit) {
    case "ms":
      return num;
    case "s":
    case "sec":
      return num * 1000;
    case "m":
    case "min":
      return num * 60 * 1000;
    case "h":
    case "hr":
      return num * 60 * 60 * 1000;
    case "d":
    case "day":
      return num * 24 * 60 * 60 * 1000;
    case "w":
    case "week":
      return num * 7 * 24 * 60 * 60 * 1000;
    default:
      return NaN;
  }
}

/**
 * ANSI 颜色代码
 */
export const COLORS = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
};

/**
 * 给文本添加 ANSI 颜色
 */
export function color(text: string, colorCode: string): string {
  return `${colorCode}${text}${COLORS.reset}`;
}

/**
 * Strip ANSI escape sequences for accurate visible-width calculation
 */
function stripAnsi(str: string): string {
  return str.replace(/\x1b\[[0-9;]*m/g, "");
}

/**
 * Pad a string (possibly containing ANSI codes) to a target visible width
 */
function padVisible(str: string, targetWidth: number): string {
  const visibleLen = stripAnsi(str).length;
  const padLen = Math.max(0, targetWidth - visibleLen);
  return str + " ".repeat(padLen);
}

/**
 * 格式化简单 ASCII 表格
 */
export function formatTable(
  headers: string[],
  rows: (string | number)[][]
): string {
  if (rows.length === 0) {
    return "No data";
  }

  // 计算列宽度 (using visible width, stripping ANSI codes)
  const colWidths = headers.map((h, i) => {
    const maxRowWidth = Math.max(
      ...rows.map((r) => stripAnsi(String(r[i] || "")).length)
    );
    return Math.max(h.length, maxRowWidth);
  });

  // 构建表格
  const lines: string[] = [];

  // 标题行
  const headerRow = headers
    .map((h, i) => h.padEnd(colWidths[i]))
    .join(" │ ");
  lines.push(headerRow);

  // 分隔线
  const separator = colWidths
    .map((w) => "─".repeat(w))
    .join("─┼─");
  lines.push(separator);

  // 数据行
  for (const row of rows) {
    const dataRow = row
      .map((cell, i) => padVisible(String(cell || ""), colWidths[i]))
      .join(" │ ");
    lines.push(dataRow);
  }

  return lines.join("\n");
}

/**
 * 加载配置文件
 * 合并来自多个源的配置: ~/.carapace/config.json 和 .carapace.yml (在当前工作目录)
 */
export function loadConfig(configPath?: string): Record<string, unknown> {
  const config: Record<string, unknown> = {};

  // 从 ~/.carapace/config.json 加载
  const homeConfigPath = join(homedir(), ".carapace", "config.json");
  if (existsSync(homeConfigPath)) {
    try {
      const content = readFileSync(homeConfigPath, "utf-8");
      const parsed = JSON.parse(content) as Record<string, unknown>;
      for (const key of Object.keys(parsed)) {
        if (key !== "__proto__" && key !== "constructor" && key !== "prototype") {
          config[key] = parsed[key];
        }
      }
    } catch {
      // 忽略加载错误
    }
  }

  // 从 .carapace.yml 加载 (当前目录)
  const cwdConfigPath = configPath || join(process.cwd(), ".carapace.yml");
  if (existsSync(cwdConfigPath)) {
    try {
      const content = readFileSync(cwdConfigPath, "utf-8");
      const parsed = parseSimpleYaml(content);
      for (const key of Object.keys(parsed)) {
        if (key !== "__proto__" && key !== "constructor" && key !== "prototype") {
          config[key] = parsed[key];
        }
      }
    } catch {
      // 忽略加载错误
    }
  }

  return config;
}

/**
 * 框架配置
 */
export interface FrameworkConfig {
  name: string;
  adapter?: string;
  description: string;
}

/**
 * 检测当前项目使用的 AI 框架
 */
export function detectFramework(): FrameworkConfig | null {
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

    if (deps.openclaw) {
      return { name: "openclaw", adapter: "openclaw", description: "OpenClaw Agent Framework" };
    }
    if (deps.langchain || deps["@langchain/core"]) {
      return { name: "langchain", adapter: "langchain", description: "LangChain Framework" };
    }
    if (deps.crewai) {
      return { name: "crewai", description: "CrewAI Framework" };
    }
    if (deps.autogen) {
      return { name: "autogen", description: "AutoGen Framework" };
    }
    if (deps["@modelcontextprotocol/sdk"]) {
      return { name: "mcp", adapter: "mcp", description: "Model Context Protocol" };
    }
  } catch {
    // 忽略解析错误
  }

  return null;
}

/**
 * 获取数据库路径
 */
export function getDbPath(): string {
  return join(homedir(), ".carapace", "carapace.db");
}

/**
 * 格式化时间戳为可读格式
 */
export function formatTime(timestamp: number): string {
  const date = new Date(timestamp);
  return date.toISOString().replace("T", " ").substring(0, 19);
}

/**
 * 解析并验证端口号
 */
export function parsePort(value: string | boolean | undefined, defaultPort: number): number {
  if (!value || typeof value === "boolean") return defaultPort;
  const port = parseInt(value, 10);
  if (isNaN(port) || port < 0 || port > 65535) {
    console.error(color(`Invalid port: ${String(value).replace(/[\x00-\x1f\x7f]/g, "")} (must be 0-65535)`, COLORS.red));
    process.exit(1);
  }
  return port;
}

/**
 * 格式化相对时间
 */
export function formatRelativeTime(timestamp: number): string {
  const now = Date.now();
  const diff = now - timestamp;

  // Handle future timestamps (e.g., dismissal expiry dates)
  if (diff < 0) {
    const absDiff = -diff;
    if (absDiff < 60000) return "in <1m";
    if (absDiff < 3600000) return `in ${Math.floor(absDiff / 60000)}m`;
    if (absDiff < 86400000) return `in ${Math.floor(absDiff / 3600000)}h`;
    return `in ${Math.floor(absDiff / 86400000)}d`;
  }

  if (diff < 60000) return "just now";
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return `${Math.floor(diff / 86400000)}d ago`;
}
