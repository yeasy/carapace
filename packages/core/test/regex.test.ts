/**
 * ReDoS safety validation tests for isRedosSafe()
 */

import { describe, it, expect } from "vitest";
import { isRedosSafe } from "../src/utils/regex.js";

describe("isRedosSafe", () => {
  describe("safe patterns", () => {
    it("should accept a simple literal pattern", () => {
      expect(isRedosSafe("foo")).toBe(true);
    });

    it("should accept a pattern with escaped dot", () => {
      expect(isRedosSafe("bar\\.com")).toBe(true);
    });

    it("should accept a character class with path separators", () => {
      expect(isRedosSafe("[/\\\\]\\.ssh[/\\\\]")).toBe(true);
    });

    it("should accept a simple quantifier without nesting", () => {
      expect(isRedosSafe("a+")).toBe(true);
    });

    it("should accept a wildcard pattern without nesting", () => {
      expect(isRedosSafe(".*")).toBe(true);
    });

    it("should accept a group without a quantifier on it", () => {
      expect(isRedosSafe("(abc)")).toBe(true);
    });

    it("should accept a non-capturing group without quantifier", () => {
      expect(isRedosSafe("(?:abc)")).toBe(true);
    });

    it("should accept an empty string", () => {
      expect(isRedosSafe("")).toBe(true);
    });

    it("should accept a character class with quantifier", () => {
      expect(isRedosSafe("[a-z]+")).toBe(true);
    });

    it("should accept a simple alternation without quantifier on group", () => {
      expect(isRedosSafe("(cat|dog)")).toBe(true);
    });
  });

  describe("dangerous patterns (nested quantifiers)", () => {
    it("should reject (a+)+", () => {
      expect(isRedosSafe("(a+)+")).toBe(false);
    });

    it("should reject (a+)*", () => {
      expect(isRedosSafe("(a+)*")).toBe(false);
    });

    it("should reject (a*)+", () => {
      expect(isRedosSafe("(a*)+")).toBe(false);
    });

    it("should reject (a*)*", () => {
      expect(isRedosSafe("(a*)*")).toBe(false);
    });

    it("should reject (.*)*", () => {
      expect(isRedosSafe("(.*)*")).toBe(false);
    });

    it("should reject (.+)+", () => {
      expect(isRedosSafe("(.+)+")).toBe(false);
    });

    it("should reject (.*)+", () => {
      expect(isRedosSafe("(.*)+")).toBe(false);
    });

    it("should reject nested quantifier with curly brace (a+){2,}", () => {
      expect(isRedosSafe("(a+){2,}")).toBe(false);
    });
  });

  describe("dangerous patterns (overlapping alternations)", () => {
    it("should reject (a|b)+", () => {
      expect(isRedosSafe("(a|b)+")).toBe(false);
    });

    it("should reject (a|b)*", () => {
      expect(isRedosSafe("(a|b)*")).toBe(false);
    });

    it("should reject (foo|bar)+", () => {
      expect(isRedosSafe("(foo|bar)+")).toBe(false);
    });

    it("should reject (x|y|z)*", () => {
      expect(isRedosSafe("(x|y|z)*")).toBe(false);
    });
  });

  describe("pattern length limit", () => {
    it("should reject patterns longer than 512 characters", () => {
      const longPattern = "a".repeat(513);
      expect(isRedosSafe(longPattern)).toBe(false);
    });

    it("should accept patterns exactly 512 characters", () => {
      const pattern = "a".repeat(512);
      expect(isRedosSafe(pattern)).toBe(true);
    });

    it("should accept patterns shorter than 512 characters", () => {
      const pattern = "a".repeat(100);
      expect(isRedosSafe(pattern)).toBe(true);
    });
  });
});
