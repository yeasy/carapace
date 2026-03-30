/**
 * redactSensitiveValues 单元测试
 */

import { describe, it, expect } from "vitest";
import { redactSensitiveValues } from "../src/utils/redact.js";

describe("redactSensitiveValues", () => {
  it("should not mutate the original object", () => {
    const original = { key: "sk-abc1234567890abcdef" };
    const result = redactSensitiveValues(original);
    expect(original.key).toBe("sk-abc1234567890abcdef");
    expect(result.key).not.toBe(original.key);
  });

  it("should redact AWS access key IDs", () => {
    const params = { config: "aws_key=AKIAIOSFODNN7EXAMPLE" };
    const result = redactSensitiveValues(params);
    expect(result.config).toBe("aws_key=[REDACTED]");
    expect((result.config as string).includes("AKIA")).toBe(false);
  });

  it("should redact API keys matching sk-xxx pattern", () => {
    const params = { authorization: "Bearer sk-proj1234567890abcdef" };
    const result = redactSensitiveValues(params);
    expect(result.authorization).toBe("Bearer [REDACTED]");
  });

  it("should redact token-style keys", () => {
    const params = { header: "token_abcdef1234567890xx" };
    const result = redactSensitiveValues(params);
    expect(result.header).toBe("[REDACTED]");
  });

  it("should redact full PEM private key block", () => {
    const params = { cert: "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----" };
    const result = redactSensitiveValues(params);
    expect(result.cert).toBe("[REDACTED]");
  });

  it("should redact PEM header when END marker is missing", () => {
    const params = { cert: "-----BEGIN PRIVATE KEY-----\nMIIE..." };
    const result = redactSensitiveValues(params);
    expect((result.cert as string).includes("BEGIN")).toBe(false);
  });

  it("should redact PASSWORD= exports", () => {
    const params = { script: "export PASSWORD=mysecretpass123" };
    const result = redactSensitiveValues(params);
    expect(result.script).toBe("export [REDACTED]");
  });

  it("should redact SECRET= exports", () => {
    const params = { script: "SECRET=hunter2 TOKEN=abc123" };
    const result = redactSensitiveValues(params);
    expect((result.script as string).includes("hunter2")).toBe(false);
    expect((result.script as string).includes("abc123")).toBe(false);
  });

  it("should handle nested objects", () => {
    const params = {
      outer: {
        inner: {
          key: "AKIAIOSFODNN7EXAMPLE",
        },
      },
    };
    const result = redactSensitiveValues(params);
    expect((result.outer as Record<string, unknown> as any).inner.key).toBe("[REDACTED]");
  });

  it("should handle arrays", () => {
    const params = {
      args: ["--token", "sk-1234567890abcdefghij"],
    };
    const result = redactSensitiveValues(params);
    expect((result.args as string[])[0]).toBe("--token");
    expect((result.args as string[])[1]).toBe("[REDACTED]");
  });

  it("should not redact non-sensitive strings", () => {
    const params = {
      command: "ls -la /home/user",
      path: "/usr/local/bin",
      name: "my-project",
    };
    const result = redactSensitiveValues(params);
    expect(result.command).toBe("ls -la /home/user");
    expect(result.path).toBe("/usr/local/bin");
    expect(result.name).toBe("my-project");
  });

  it("should only redact the sensitive portion, not the entire string", () => {
    const params = {
      command: "curl -H 'Authorization: Bearer sk-proj1234567890abcdef' https://api.example.com",
    };
    const result = redactSensitiveValues(params);
    expect((result.command as string).includes("curl")).toBe(true);
    expect((result.command as string).includes("https://api.example.com")).toBe(true);
    expect((result.command as string).includes("sk-proj1234567890abcdef")).toBe(false);
  });

  it("should handle empty objects", () => {
    const result = redactSensitiveValues({});
    expect(result).toEqual({});
  });

  it("should handle non-string values without modification", () => {
    const params = { count: 42, enabled: true, data: null };
    const result = redactSensitiveValues(params);
    expect(result.count).toBe(42);
    expect(result.enabled).toBe(true);
    expect(result.data).toBe(null);
  });

  it("should redact API_KEY= pattern", () => {
    const params = { env: "API_KEY=sk_live_abcdef123456" };
    const result = redactSensitiveValues(params);
    expect((result.env as string).includes("sk_live_abcdef123456")).toBe(false);
  });

  it("works correctly on consecutive calls (no stale regex state)", () => {
    const r1 = redactSensitiveValues({ key: "AKIAIOSFODNN7EXAMPLE" });
    const r2 = redactSensitiveValues({ key: "AKIAIOSFODNN7EXAMPLE" });
    expect(r1.key).toBe("[REDACTED]");
    expect(r2.key).toBe("[REDACTED]");
  });

  it("should redact JWT tokens", () => {
    const params = {
      auth: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    };
    const result = redactSensitiveValues(params);
    expect((result.auth as string).includes("eyJ")).toBe(false);
  });

  it("should redact JWT tokens embedded in a larger string", () => {
    const params = {
      command:
        "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U' https://api.example.com",
    };
    const result = redactSensitiveValues(params);
    expect((result.command as string).includes("curl")).toBe(true);
    expect((result.command as string).includes("eyJ")).toBe(false);
  });

  it("should redact Slack tokens", () => {
    const params = { token: "xoxb-1234567890-abcdefghij" };
    const result = redactSensitiveValues(params);
    expect((result.token as string).includes("xoxb")).toBe(false);
  });

  it("should redact various Slack token types", () => {
    const params = {
      botToken: "xoxb-1234567890-abcdefghij",
      userToken: "xoxp-9876543210-zyxwvutsrq",
    };
    const result = redactSensitiveValues(params);
    expect((result.botToken as string).includes("xoxb")).toBe(false);
    expect((result.userToken as string).includes("xoxp")).toBe(false);
  });

  it("should redact GitHub fine-grained PATs", () => {
    const params = { token: "github_pat_11ABCDEFG0abcdefghijklmnopqrstuvwxyz1234567890" };
    const result = redactSensitiveValues(params);
    expect((result.token as string).includes("github_pat_")).toBe(false);
  });

  it("should redact connection strings with credentials", () => {
    const params = {
      dsn: "postgres://admin:supersecret@db.example.com:5432/mydb",
    };
    const result = redactSensitiveValues(params);
    expect((result.dsn as string).includes("supersecret")).toBe(false);
    expect((result.dsn as string).includes("db.example.com")).toBe(true);
  });

  it("should redact various database connection strings", () => {
    const params = {
      pg: "postgres://user:pass123@host:5432/db",
      mongo: "mongodb://root:secret@mongo.example.com:27017/admin",
      mysql: "mysql://app:dbpass@mysql.local:3306/appdb",
      redis: "redis://default:redispass@redis.example.com:6379",
    };
    const result = redactSensitiveValues(params);
    expect((result.pg as string).includes("pass123")).toBe(false);
    expect((result.mongo as string).includes("secret")).toBe(false);
    expect((result.mysql as string).includes("dbpass")).toBe(false);
    expect((result.redis as string).includes("redispass")).toBe(false);
  });

  it("should redact Bearer tokens in headers", () => {
    const params = {
      header: "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9abcdefghijklmn",
    };
    const result = redactSensitiveValues(params);
    expect((result.header as string).includes("eyJhbGci")).toBe(false);
  });

  it("should redact Authorization header values", () => {
    const params = {
      header: "Authorization: abcdefghijklmnopqrstuvwxyz1234567890ABCDEF",
    };
    const result = redactSensitiveValues(params);
    expect((result.header as string).includes("abcdefghijklmnopqrstuvwxyz")).toBe(false);
  });

  it("should use head+tail sampling for strings exceeding MAX_REDACT_LEN (16384)", () => {
    const longString = "A".repeat(20000);
    const params = { data: longString };
    const result = redactSensitiveValues(params);
    expect((result.data as string).includes("[...TRUNCATED...]")).toBe(true);
    // The result should be shorter than the original
    expect((result.data as string).length).toBeLessThan(longString.length);
  });

  it("should redact secrets at the tail of long strings via head+tail sampling", () => {
    // Place a secret at position 17000 — beyond the old 16384 cap
    const padding = "X".repeat(17000);
    const secret = "AKIAIOSFODNN7EXAMPLE";
    const longString = padding + secret;
    const params = { data: longString };
    const result = redactSensitiveValues(params);
    // The tail portion should have the AWS key redacted
    expect((result.data as string).includes("AKIA")).toBe(false);
    expect((result.data as string).includes("[REDACTED]")).toBe(true);
  });

  it("should handle deeply nested objects without stack overflow", () => {
    // Build a 30-level deep nested object (exceeds MAX_REDACT_DEPTH=20)
    let obj: Record<string, unknown> = { secret: "sk-deep1234567890abcdef" };
    for (let i = 0; i < 30; i++) {
      obj = { nested: obj };
    }
    // Should not throw (depth limit prevents stack overflow)
    const result = redactSensitiveValues(obj);
    expect(result).toBeDefined();
  });

  it("should handle circular-reference objects without crashing", () => {
    // structuredClone handles circular refs, depth limit prevents infinite walk
    const obj: Record<string, unknown> = { a: "sk-secret1234567890abcdef" };
    obj.self = obj; // circular reference
    const result = redactSensitiveValues(obj);
    // Should not crash — either clones successfully or returns error marker
    expect(result).toBeDefined();
    // If cloned successfully, the secret should be redacted
    if (!result._redactionError) {
      expect((result.a as string).includes("sk-secret")).toBe(false);
    }
  });

  it("should handle empty object", () => {
    const result = redactSensitiveValues({});
    expect(result).toEqual({});
  });

  it("should redact Anthropic API keys (sk-ant-*)", () => {
    const params = { key: "prefix sk-ant-api03-abcdefghijklmnopqrst suffix" };
    const result = redactSensitiveValues(params);
    expect((result.key as string).includes("sk-ant-")).toBe(false);
  });

  it("should redact Google API keys (AIzaSy*)", () => {
    const params = { key: "AIzaSyA1234567890abcdefghijklmnopqrstuvw" };
    const result = redactSensitiveValues(params);
    expect((result.key as string).includes("AIzaSy")).toBe(false);
  });

  it("should redact GitHub OAuth tokens (gho_*)", () => {
    const params = { token: "gho_abcdefghijklmnopqrstuvwxyz1234567890" };
    const result = redactSensitiveValues(params);
    expect((result.token as string).includes("gho_")).toBe(false);
  });
});
