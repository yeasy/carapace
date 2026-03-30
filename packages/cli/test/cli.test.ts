/**
 * CLI 测试
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  parseArgs,
  parseDuration,
  formatTable,
  color,
  COLORS,
  formatTime,
  formatRelativeTime,
} from "../src/utils.js";

describe("parseArgs", () => {
  it("should parse simple command", () => {
    const result = parseArgs(["node", "cli", "status"]);
    expect(result.command).toBe("status");
    expect(result.args).toEqual([]);
    expect(result.flags).toEqual({});
  });

  it("should parse command with positional args", () => {
    const result = parseArgs(["node", "cli", "skills", "inspect", "myskill"]);
    expect(result.command).toBe("skills");
    expect(result.args).toEqual(["inspect", "myskill"]);
  });

  it("should parse long flags with values", () => {
    const result = parseArgs([
      "node",
      "cli",
      "events",
      "--severity",
      "critical",
      "--limit",
      "50",
    ]);
    expect(result.command).toBe("events");
    expect(result.flags.severity).toBe("critical");
    expect(result.flags.limit).toBe("50");
  });

  it("should parse short flags", () => {
    const result = parseArgs(["node", "cli", "events", "-s", "high"]);
    expect(result.command).toBe("events");
    expect(result.flags.s).toBe("high");
  });

  it("should parse boolean flags", () => {
    const result = parseArgs(["node", "cli", "events", "--verbose"]);
    expect(result.command).toBe("events");
    expect(result.flags.verbose).toBe(true);
  });

  it("should handle mixed args and flags", () => {
    const result = parseArgs([
      "node",
      "cli",
      "report",
      "session-123",
      "--format",
      "json",
    ]);
    expect(result.command).toBe("report");
    expect(result.args[0]).toBe("session-123");
    expect(result.flags.format).toBe("json");
  });
});

describe("parseDuration", () => {
  it("should parse milliseconds", () => {
    expect(parseDuration("1000ms")).toBe(1000);
    expect(parseDuration("500ms")).toBe(500);
  });

  it("should parse seconds", () => {
    expect(parseDuration("30s")).toBe(30000);
    expect(parseDuration("1sec")).toBe(1000);
  });

  it("should parse minutes", () => {
    expect(parseDuration("30m")).toBe(30 * 60 * 1000);
    expect(parseDuration("5min")).toBe(5 * 60 * 1000);
  });

  it("should parse hours", () => {
    expect(parseDuration("24h")).toBe(24 * 60 * 60 * 1000);
    expect(parseDuration("2hr")).toBe(2 * 60 * 60 * 1000);
  });

  it("should parse days", () => {
    expect(parseDuration("7d")).toBe(7 * 24 * 60 * 60 * 1000);
    expect(parseDuration("1day")).toBe(24 * 60 * 60 * 1000);
  });

  it("should parse weeks", () => {
    expect(parseDuration("1w")).toBe(7 * 24 * 60 * 60 * 1000);
    expect(parseDuration("2week")).toBe(2 * 7 * 24 * 60 * 60 * 1000);
  });

  it("should return NaN for invalid format", () => {
    expect(parseDuration("invalid")).toBeNaN();
    expect(parseDuration("xxx")).toBeNaN();
  });
});

describe("formatTable", () => {
  it("should format simple table", () => {
    const headers = ["Name", "Age"];
    const rows = [
      ["Alice", 30],
      ["Bob", 25],
    ];
    const result = formatTable(headers, rows);
    expect(result).toContain("Name");
    expect(result).toContain("Age");
    expect(result).toContain("Alice");
    expect(result).toContain("Bob");
  });

  it("should handle wide columns", () => {
    const headers = ["Short", "LongerColumnName"];
    const rows = [["A", "B"]];
    const result = formatTable(headers, rows);
    expect(result).toContain("Short");
    expect(result).toContain("LongerColumnName");
  });

  it("should align columns properly", () => {
    const headers = ["Col1", "Col2"];
    const rows = [
      ["abc", "def"],
      ["ghij", "kl"],
    ];
    const result = formatTable(headers, rows);
    const lines = result.split("\n");
    // 第一列应该对齐
    expect(lines[0]).toContain("Col1");
    expect(lines[2]).toContain("abc");
  });

  it("should return 'No data' for empty rows", () => {
    const headers = ["Name"];
    const rows: any[] = [];
    const result = formatTable(headers, rows);
    expect(result).toBe("No data");
  });
});

describe("color", () => {
  it("should wrap text with color code", () => {
    const result = color("test", COLORS.red);
    expect(result).toContain("\x1b[31m");
    expect(result).toContain("test");
    expect(result).toContain("\x1b[0m");
  });

  it("should handle different colors", () => {
    expect(color("a", COLORS.green)).toContain("\x1b[32m");
    expect(color("b", COLORS.yellow)).toContain("\x1b[33m");
    expect(color("c", COLORS.blue)).toContain("\x1b[34m");
  });
});

describe("formatTime", () => {
  it("should format timestamp as ISO string", () => {
    const ts = new Date("2025-03-11T10:30:45Z").getTime();
    const result = formatTime(ts);
    expect(result).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
  });

  it("should handle current time", () => {
    const now = Date.now();
    const result = formatTime(now);
    expect(result).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
  });
});

describe("formatRelativeTime", () => {
  it("should show 'just now' for recent time", () => {
    const now = Date.now();
    const result = formatRelativeTime(now);
    expect(result).toBe("just now");
  });

  it("should show minutes ago", () => {
    const now = Date.now();
    const fiveMinutesAgo = now - 5 * 60 * 1000;
    const result = formatRelativeTime(fiveMinutesAgo);
    expect(result).toMatch(/^\d+m ago$/);
  });

  it("should show hours ago", () => {
    const now = Date.now();
    const twoHoursAgo = now - 2 * 60 * 60 * 1000;
    const result = formatRelativeTime(twoHoursAgo);
    expect(result).toMatch(/^\d+h ago$/);
  });

  it("should show days ago", () => {
    const now = Date.now();
    const threeDaysAgo = now - 3 * 24 * 60 * 60 * 1000;
    const result = formatRelativeTime(threeDaysAgo);
    expect(result).toMatch(/^\d+d ago$/);
  });
});

describe("Integration Tests", () => {
  it("should parse and handle events command", () => {
    const result = parseArgs([
      "node",
      "cli",
      "events",
      "--severity",
      "critical",
      "--since",
      "24h",
      "--limit",
      "50",
      "--export",
      "csv",
    ]);

    expect(result.command).toBe("events");
    expect(result.flags.severity).toBe("critical");
    expect(result.flags.since).toBe("24h");

    // 应该能解析时间
    const duration = parseDuration(String(result.flags.since));
    expect(duration).toBe(24 * 60 * 60 * 1000);
  });

  it("should parse skills inspect command", () => {
    const result = parseArgs([
      "node",
      "cli",
      "skills",
      "inspect",
      "calendar-sync",
    ]);

    expect(result.command).toBe("skills");
    expect(result.args[0]).toBe("inspect");
    expect(result.args[1]).toBe("calendar-sync");
  });

  it("should parse trust command with options", () => {
    const result = parseArgs([
      "node",
      "cli",
      "trust",
      "my-skill",
      "--tool",
      "curl",
      "--path",
      "/tmp/data",
    ]);

    expect(result.command).toBe("trust");
    expect(result.args[0]).toBe("my-skill");
    expect(result.flags.tool).toBe("curl");
    expect(result.flags.path).toBe("/tmp/data");
  });

  it("should handle report command with session id", () => {
    const result = parseArgs([
      "node",
      "cli",
      "report",
      "abc123def456",
    ]);

    expect(result.command).toBe("report");
    expect(result.args[0]).toBe("abc123def456");
  });

  it("should handle baseline reset", () => {
    const result = parseArgs([
      "node",
      "cli",
      "baseline",
      "reset",
      "my-skill",
    ]);

    expect(result.command).toBe("baseline");
    expect(result.args[0]).toBe("reset");
    expect(result.args[1]).toBe("my-skill");
  });

  it("should handle dismiss list", () => {
    const result = parseArgs(["node", "cli", "dismissals", "list"]);

    expect(result.command).toBe("dismissals");
    expect(result.args[0]).toBe("list");
  });

  it("should handle dismiss clear", () => {
    const result = parseArgs(["node", "cli", "dismissals", "clear"]);

    expect(result.command).toBe("dismissals");
    expect(result.args[0]).toBe("clear");
  });
});
