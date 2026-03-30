/**
 * CLI 补充测试 — 边界场景和未覆盖的工具函数
 */

import { describe, it, expect } from "vitest";
import {
  parseArgs,
  parseDuration,
  formatTable,
  color,
  COLORS,
  formatTime,
  formatRelativeTime,
  loadConfig,
  getDbPath,
} from "../src/utils.js";

describe("CLI utils extras", () => {
  describe("parseArgs extras", () => {
    it("returns null command when no command given", () => {
      const result = parseArgs(["node", "script.js"]);
      expect(result.command).toBeNull();
    });

    it("handles empty argv gracefully", () => {
      const result = parseArgs([]);
      expect(result).toBeDefined();
      expect(result.args).toEqual([]);
      expect(result.flags).toEqual({});
    });

    it("parses consecutive boolean flags", () => {
      // parseArgs treats first non-node/script arg as command
      const result = parseArgs(["node", "cli", "cmd", "--verbose", "--debug"]);
      expect(result.flags.verbose).toBe(true);
      expect(result.flags.debug).toBe(true);
    });

    it("parses short boolean flag", () => {
      const result = parseArgs(["node", "cli", "cmd", "-v"]);
      expect(result.flags.v).toBe(true);
    });

    it("handles flag at end of argv", () => {
      const result = parseArgs(["node", "cli", "cmd", "--json"]);
      expect(result.flags.json).toBe(true);
    });

    it("handles flag with -- prefix and next flag as value", () => {
      // --flag1 --flag2 → flag1 should be boolean (next starts with --)
      const result = parseArgs(["node", "cli", "cmd", "--flag1", "--flag2"]);
      expect(result.flags.flag1).toBe(true);
      expect(result.flags.flag2).toBe(true);
    });
  });

  describe("parseDuration extras", () => {
    it('"0ms" returns 0', () => {
      expect(parseDuration("0ms")).toBe(0);
    });

    it("empty string returns NaN", () => {
      expect(parseDuration("")).toBeNaN();
    });

    it("just number without unit returns NaN", () => {
      expect(parseDuration("123")).toBeNaN();
    });

    it("unknown unit returns NaN", () => {
      expect(parseDuration("5xyz")).toBeNaN();
    });
  });

  describe("formatTable extras", () => {
    it("single row table", () => {
      const result = formatTable(["Name", "Value"], [["test", 42]]);
      expect(result).toContain("Name");
      expect(result).toContain("test");
      expect(result).toContain("42");
    });

    it("numeric values render correctly", () => {
      const result = formatTable(["ID", "Count"], [[1, 100], [2, 200]]);
      expect(result).toContain("100");
      expect(result).toContain("200");
    });

    it("handles empty/null cell values", () => {
      const result = formatTable(["A", "B"], [["x", ""], ["", "y"]]);
      expect(typeof result).toBe("string");
      expect(result).toContain("x");
      expect(result).toContain("y");
    });

    it("table with very wide column values", () => {
      const longValue = "a".repeat(50);
      const result = formatTable(["Col"], [[longValue]]);
      expect(result).toContain(longValue);
    });
  });

  describe("color extras", () => {
    it("handles empty string", () => {
      const result = color("", COLORS.red);
      expect(result).toContain(COLORS.red);
      expect(result).toContain(COLORS.reset);
    });

    it("handles string with ANSI codes inside", () => {
      const result = color("already\x1b[31m colored", COLORS.blue);
      expect(result.startsWith(COLORS.blue)).toBe(true);
    });
  });

  describe("formatTime extras", () => {
    it("produces consistent ISO-like format", () => {
      const ts = new Date("2026-03-11T12:30:45Z").getTime();
      const result = formatTime(ts);
      expect(result).toMatch(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/);
    });

    it("handles epoch 0", () => {
      const result = formatTime(0);
      expect(result).toContain("1970");
    });
  });

  describe("formatRelativeTime extras", () => {
    it("exactly 60 seconds ago shows minutes", () => {
      const result = formatRelativeTime(Date.now() - 60000);
      expect(result).toMatch(/1m ago/);
    });

    it("exactly 1 hour ago shows hours", () => {
      const result = formatRelativeTime(Date.now() - 3600000);
      expect(result).toMatch(/1h ago/);
    });

    it("exactly 1 day ago shows days", () => {
      const result = formatRelativeTime(Date.now() - 86400000);
      expect(result).toMatch(/1d ago/);
    });

    it("very recent timestamp shows 'just now'", () => {
      const result = formatRelativeTime(Date.now() - 5000);
      expect(result).toBe("just now");
    });

    it("future timestamp shows 'in Xh' format", () => {
      const result = formatRelativeTime(Date.now() + 7200000);
      expect(result).toMatch(/^in 2h$/);
    });

    it("near-future timestamp shows 'in <1m'", () => {
      const result = formatRelativeTime(Date.now() + 30000);
      expect(result).toBe("in <1m");
    });

    it("future days shows 'in Xd' format", () => {
      const result = formatRelativeTime(Date.now() + 172800000);
      expect(result).toMatch(/^in 2d$/);
    });
  });

  describe("getDbPath", () => {
    it("returns path containing .carapace", () => {
      const result = getDbPath();
      expect(result).toContain(".carapace");
      expect(result).toContain("carapace.db");
    });
  });

  describe("loadConfig", () => {
    it("returns object even without config files", () => {
      const result = loadConfig();
      expect(typeof result).toBe("object");
      expect(result).not.toBeNull();
    });
  });
});
