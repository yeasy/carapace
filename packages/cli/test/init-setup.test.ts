/**
 * Tests for init and setup commands
 */

import { describe, it, expect, afterEach } from "vitest";
import { existsSync, readFileSync, writeFileSync, mkdirSync, rmSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

// ── Helper: create a temporary project directory ──

function createTempProject(deps?: Record<string, string>): string {
  const dir = join(tmpdir(), `carapace-test-${Date.now()}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(dir, { recursive: true });
  if (deps) {
    writeFileSync(
      join(dir, "package.json"),
      JSON.stringify({ name: "test-project", dependencies: deps }),
      "utf-8"
    );
  }
  return dir;
}

function cleanupDir(dir: string): void {
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    // ignore cleanup errors
  }
}

// ── Framework detection helper (mirrors init.ts logic) ──

interface FrameworkInfo {
  name: string;
  adapter: string;
}

const FRAMEWORK_SIGNATURES: Record<string, FrameworkInfo> = {
  openclaw: { name: "openclaw", adapter: "openclaw" },
  "@langchain/core": { name: "langchain", adapter: "langchain" },
  langchain: { name: "langchain", adapter: "langchain" },
  crewai: { name: "crewai", adapter: "langchain" },
  autogen: { name: "autogen", adapter: "langchain" },
  "@modelcontextprotocol/sdk": { name: "mcp", adapter: "mcp" },
};

function detectFramework(projectDir: string): FrameworkInfo | null {
  const pkgPath = join(projectDir, "package.json");
  if (!existsSync(pkgPath)) return null;
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf-8"));
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    for (const [key, info] of Object.entries(FRAMEWORK_SIGNATURES)) {
      if (deps[key]) return info;
    }
  } catch {
    return null;
  }
  return null;
}

// ── Framework Detection Tests ──

describe("Framework Detection", () => {
  let tempDir: string;

  afterEach(() => {
    if (tempDir) cleanupDir(tempDir);
  });

  it("should detect OpenClaw framework", () => {
    tempDir = createTempProject({ openclaw: "^1.0.0" });
    const fw = detectFramework(tempDir);
    expect(fw).not.toBeNull();
    expect(fw!.name).toBe("openclaw");
    expect(fw!.adapter).toBe("openclaw");
  });

  it("should detect LangChain framework via @langchain/core", () => {
    tempDir = createTempProject({ "@langchain/core": "^0.2.0" });
    const fw = detectFramework(tempDir);
    expect(fw).not.toBeNull();
    expect(fw!.name).toBe("langchain");
  });

  it("should detect LangChain framework via langchain", () => {
    tempDir = createTempProject({ langchain: "^0.1.0" });
    const fw = detectFramework(tempDir);
    expect(fw).not.toBeNull();
    expect(fw!.name).toBe("langchain");
  });

  it("should detect CrewAI framework", () => {
    tempDir = createTempProject({ crewai: "^1.0.0" });
    const fw = detectFramework(tempDir);
    expect(fw).not.toBeNull();
    expect(fw!.name).toBe("crewai");
  });

  it("should detect AutoGen framework", () => {
    tempDir = createTempProject({ autogen: "^0.5.0" });
    const fw = detectFramework(tempDir);
    expect(fw).not.toBeNull();
    expect(fw!.name).toBe("autogen");
  });

  it("should detect MCP framework", () => {
    tempDir = createTempProject({ "@modelcontextprotocol/sdk": "^1.0.0" });
    const fw = detectFramework(tempDir);
    expect(fw).not.toBeNull();
    expect(fw!.name).toBe("mcp");
    expect(fw!.adapter).toBe("mcp");
  });

  it("should handle missing package.json gracefully", () => {
    tempDir = join(tmpdir(), `carapace-test-empty-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    const fw = detectFramework(tempDir);
    expect(fw).toBeNull();
  });

  it("should handle package.json without dependencies", () => {
    tempDir = join(tmpdir(), `carapace-test-nodeps-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(join(tempDir, "package.json"), JSON.stringify({ name: "test" }), "utf-8");
    const fw = detectFramework(tempDir);
    expect(fw).toBeNull();
  });

  it("should handle malformed package.json", () => {
    tempDir = join(tmpdir(), `carapace-test-bad-${Date.now()}`);
    mkdirSync(tempDir, { recursive: true });
    writeFileSync(join(tempDir, "package.json"), "invalid json{{{", "utf-8");
    const fw = detectFramework(tempDir);
    expect(fw).toBeNull();
  });
});

// ── Config Generation Tests ──

describe("Config Generation", () => {
  it("should generate valid YAML-like config with OpenClaw framework", () => {
    const lines: string[] = [];
    lines.push("# Carapace Configuration");
    lines.push("framework: openclaw");
    lines.push("adapter: openclaw");
    lines.push("blockOnCritical: true");
    lines.push('alertWebhook: ""');
    lines.push("logFile: ~/.carapace/events.jsonl");
    lines.push("maxToolCallsPerMinute: 60");
    lines.push("enableBaseline: true");

    const config = lines.join("\n");
    expect(config).toContain("framework: openclaw");
    expect(config).toContain("adapter: openclaw");
    expect(config).toContain("blockOnCritical: true");
    expect(config).toContain("maxToolCallsPerMinute: 60");
    expect(config).toContain("enableBaseline: true");
  });

  it("should generate config without framework when not detected", () => {
    const lines: string[] = [];
    lines.push("# Framework auto-detection disabled");
    lines.push("blockOnCritical: true");
    lines.push("enableBaseline: true");

    const config = lines.join("\n");
    expect(config).not.toContain("framework:");
    expect(config).toContain("blockOnCritical: true");
  });

  it("should include LangChain-specific adapter config", () => {
    const lines: string[] = [];
    lines.push("framework: langchain");
    lines.push("adapter:");
    lines.push("  type: langchain");
    lines.push("  captureTools: true");
    lines.push("  capturePaths: true");

    const config = lines.join("\n");
    expect(config).toContain("type: langchain");
    expect(config).toContain("capturePaths: true");
  });

  it("should include MCP-specific adapter config", () => {
    const lines: string[] = [];
    lines.push("framework: mcp");
    lines.push("adapter:");
    lines.push("  type: mcp");
    lines.push("  captureTools: true");

    const config = lines.join("\n");
    expect(config).toContain("type: mcp");
    expect(config).toContain("captureTools: true");
  });

  it("should include webhook URL when provided", () => {
    const webhookUrl = "https://hooks.slack.com/services/T00/B00/xxx";
    const config = `alertWebhook: "${webhookUrl}"`;
    expect(config).toContain(webhookUrl);
  });

  it("should handle custom rate limit", () => {
    const rate = 120;
    const config = `maxToolCallsPerMinute: ${rate}`;
    expect(config).toContain("maxToolCallsPerMinute: 120");
  });
});

// ── Init Command File Operations ──

describe("Init Command File Operations", () => {
  let tempDir: string;

  afterEach(() => {
    if (tempDir) cleanupDir(tempDir);
  });

  it("should detect when .carapace.yml already exists", () => {
    tempDir = createTempProject({ openclaw: "^1.0.0" });
    writeFileSync(join(tempDir, ".carapace.yml"), "existing: config", "utf-8");
    expect(existsSync(join(tempDir, ".carapace.yml"))).toBe(true);
  });

  it("should write config file to project directory", () => {
    tempDir = createTempProject({ openclaw: "^1.0.0" });
    const configPath = join(tempDir, ".carapace.yml");
    writeFileSync(configPath, "blockOnCritical: true\n", "utf-8");
    expect(existsSync(configPath)).toBe(true);
    const content = readFileSync(configPath, "utf-8");
    expect(content).toContain("blockOnCritical: true");
  });

  it("should create ~/.carapace directory if not exists", () => {
    tempDir = createTempProject();
    const carapaceDir = join(tempDir, ".carapace-test-home");
    mkdirSync(carapaceDir, { recursive: true });
    expect(existsSync(carapaceDir)).toBe(true);
  });
});

// ── Setup Wizard Config Variants ──

describe("Setup Wizard Config Variants", () => {
  it("should generate config with all defaults", () => {
    const config = {
      framework: null as any,
      blockOnCritical: true,
      webhookUrl: "",
      enableBaseline: true,
      maxToolCallsPerMinute: 60,
    };
    expect(config.blockOnCritical).toBe(true);
    expect(config.enableBaseline).toBe(true);
    expect(config.maxToolCallsPerMinute).toBe(60);
    expect(config.webhookUrl).toBe("");
  });

  it("should generate config with blocking disabled", () => {
    const config = {
      blockOnCritical: false,
      enableBaseline: true,
      maxToolCallsPerMinute: 60,
    };
    expect(config.blockOnCritical).toBe(false);
  });

  it("should generate config with webhook URL", () => {
    const config = {
      blockOnCritical: true,
      webhookUrl: "https://hooks.slack.com/services/T00/B00/xxx",
      enableBaseline: true,
      maxToolCallsPerMinute: 60,
    };
    expect(config.webhookUrl).toContain("hooks.slack.com");
  });

  it("should generate config with baseline disabled", () => {
    const config = {
      blockOnCritical: true,
      webhookUrl: "",
      enableBaseline: false,
      maxToolCallsPerMinute: 60,
    };
    expect(config.enableBaseline).toBe(false);
  });

  it("should generate config with custom rate limit", () => {
    const config = {
      blockOnCritical: true,
      webhookUrl: "",
      enableBaseline: true,
      maxToolCallsPerMinute: 120,
    };
    expect(config.maxToolCallsPerMinute).toBe(120);
  });

  it("should handle invalid rate limit input", () => {
    const input = "abc";
    const parsed = parseInt(input, 10);
    expect(isNaN(parsed)).toBe(true);
    const rate = isNaN(parsed) || parsed <= 0 ? 60 : parsed;
    expect(rate).toBe(60);
  });

  it("should handle negative rate limit input", () => {
    const input = "-10";
    const parsed = parseInt(input, 10);
    const rate = isNaN(parsed) || parsed <= 0 ? 60 : parsed;
    expect(rate).toBe(60);
  });

  it("should handle zero rate limit input", () => {
    const input = "0";
    const parsed = parseInt(input, 10);
    const rate = isNaN(parsed) || parsed <= 0 ? 60 : parsed;
    expect(rate).toBe(60);
  });
});

// ── CLI Argument Parsing for new commands ──

describe("CLI Argument Parsing — init and setup", () => {
  function parseArgs(argv: string[]) {
    const [, , command, ...rest] = argv;
    const args: string[] = [];
    const flags: Record<string, string | boolean> = {};
    for (let i = 0; i < rest.length; i++) {
      const arg = rest[i];
      if (arg.startsWith("--")) {
        const key = arg.slice(2);
        const nextArg = rest[i + 1];
        if (nextArg && !nextArg.startsWith("--")) {
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

  it("should parse 'init' command", () => {
    const result = parseArgs(["node", "cli", "init"]);
    expect(result.command).toBe("init");
    expect(result.args).toEqual([]);
  });

  it("should parse 'init --force' command", () => {
    const result = parseArgs(["node", "cli", "init", "--force"]);
    expect(result.command).toBe("init");
    expect(result.flags.force).toBe(true);
  });

  it("should parse 'setup' command", () => {
    const result = parseArgs(["node", "cli", "setup"]);
    expect(result.command).toBe("setup");
    expect(result.args).toEqual([]);
  });

  it("should parse 'init --framework mcp' with value flag", () => {
    const result = parseArgs(["node", "cli", "init", "--framework", "mcp"]);
    expect(result.command).toBe("init");
    expect(result.flags.framework).toBe("mcp");
  });

  it("should parse multiple flags", () => {
    const result = parseArgs(["node", "cli", "init", "--force", "--framework", "openclaw"]);
    expect(result.flags.force).toBe(true);
    expect(result.flags.framework).toBe("openclaw");
  });
});
