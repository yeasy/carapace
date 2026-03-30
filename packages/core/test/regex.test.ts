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

  describe("safe patterns (literal-only alternations with quantifiers)", () => {
    it("should accept (a|b)+ as literal-only alternation", () => {
      expect(isRedosSafe("(a|b)+")).toBe(true);
    });

    it("should accept (a|b)* as literal-only alternation", () => {
      expect(isRedosSafe("(a|b)*")).toBe(true);
    });

    it("should accept (foo|bar)+ as literal-only alternation", () => {
      expect(isRedosSafe("(foo|bar)+")).toBe(true);
    });

    it("should accept (x|y|z)* as literal-only alternation", () => {
      expect(isRedosSafe("(x|y|z)*")).toBe(true);
    });
  });

  describe("overlapping literal alternation detection", () => {
    it("should reject (a|a)+ — duplicate branches cause ReDoS", () => {
      expect(isRedosSafe("(a|a)+")).toBe(false);
    });

    it("should reject (ab|ab)+ — duplicate literal branches", () => {
      expect(isRedosSafe("(ab|ab)+")).toBe(false);
    });

    it("should reject (a|ab)+ — prefix-overlapping branches", () => {
      expect(isRedosSafe("(a|ab)+")).toBe(false);
    });

    it("should reject (foo|foobar)+ — prefix-overlapping branches", () => {
      expect(isRedosSafe("(foo|foobar)+")).toBe(false);
    });

    it("should accept (abc|def)+ — non-overlapping distinct branches", () => {
      expect(isRedosSafe("(abc|def)+")).toBe(true);
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

  describe("backreference detection", () => {
    it("should reject backreference pattern (a)\\1+", () => {
      expect(isRedosSafe("(a)\\1+")).toBe(false);
    });

    it("should reject backreference pattern (.*)\\1", () => {
      expect(isRedosSafe("(.*)\\1")).toBe(false);
    });

    it("should reject multi-digit backreference \\2", () => {
      expect(isRedosSafe("(a)(b)\\2")).toBe(false);
    });

    it("should accept \\0 which is not a backreference", () => {
      expect(isRedosSafe("\\0")).toBe(true);
    });
  });
});
