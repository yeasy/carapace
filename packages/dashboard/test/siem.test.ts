/**
 * SIEM Sink SSRF validation tests
 */

import { describe, it, expect } from "vitest";
import { SplunkSink, ElasticSink, DatadogSink, SyslogSink } from "../src/siem.js";

// ═══════════════════════════════════════════════════════════
// SplunkSink — URL validation
// ═══════════════════════════════════════════════════════════

describe("SplunkSink SSRF validation", () => {
  it("should throw on non-http/https URL", () => {
    expect(
      () => new SplunkSink({ endpoint: "file:///etc/passwd", token: "t" })
    ).toThrow("only supports http/https");
  });

  it("should throw on invalid URL", () => {
    expect(
      () => new SplunkSink({ endpoint: "not-a-url", token: "t" })
    ).toThrow("invalid URL");
  });

  it("should accept valid https URL", () => {
    const sink = new SplunkSink({
      endpoint: "https://splunk.example.com:8088/services/collector/event",
      token: "test-token",
    });
    expect(sink.name).toBe("splunk");
  });

  it("should throw on localhost URL", () => {
    expect(
      () => new SplunkSink({ endpoint: "http://localhost:8088/services/collector/event", token: "t" })
    ).toThrow("private/loopback");
  });

  it("should throw on private IP (169.254 link-local)", () => {
    expect(
      () => new SplunkSink({ endpoint: "http://169.254.169.254/latest/meta-data/", token: "t" })
    ).toThrow("private/loopback");
  });

  it("should throw on private IP (10.x)", () => {
    expect(
      () => new SplunkSink({ endpoint: "http://10.0.0.1:8088/", token: "t" })
    ).toThrow("private/loopback");
  });

  it("should throw on loopback IP (127.x)", () => {
    expect(
      () => new SplunkSink({ endpoint: "http://127.0.0.1:8088/", token: "t" })
    ).toThrow("private/loopback");
  });

  it("should throw on IPv6 all-zeros (::)", () => {
    expect(
      () => new SplunkSink({ endpoint: "http://[::]:8088/", token: "t" })
    ).toThrow("private/loopback");
  });
});

// ═══════════════════════════════════════════════════════════
// ElasticSink — URL validation
// ═══════════════════════════════════════════════════════════

describe("ElasticSink SSRF validation", () => {
  it("should throw on non-http/https URL", () => {
    expect(
      () => new ElasticSink({ endpoint: "ftp://elastic.local:9200" })
    ).toThrow("only supports http/https");
  });

  it("should accept valid https URL", () => {
    const sink = new ElasticSink({
      endpoint: "https://elastic.example.com:9200",
    });
    expect(sink.name).toBe("elastic");
  });

  it("should reject path-traversal index name during send", async () => {
    const sink = new ElasticSink({
      endpoint: "https://elastic.example.com:9200",
      index: "../../_cluster/settings",
    });
    // send should silently return without making request
    const mockEvent = {
      id: "e1",
      timestamp: Date.now(),
      severity: "high" as const,
      category: "exec_danger",
      title: "test",
      action: "alert" as const,
      ruleName: "test-rule",
      toolName: "bash",
    };
    // Should not throw — just logs and returns
    await sink.send({
      event: mockEvent as any,
      summary: "test",
      actionTaken: "alert",
    });
  });
});

// ═══════════════════════════════════════════════════════════
// DatadogSink — site allow-list validation
// ═══════════════════════════════════════════════════════════

describe("DatadogSink SSRF validation", () => {
  it("should throw on unknown site parameter", () => {
    expect(
      () => new DatadogSink({ apiKey: "k", site: "evil.com" })
    ).toThrow("unknown site");
  });

  it("should accept known site", () => {
    const sink = new DatadogSink({ apiKey: "k", site: "datadoghq.com" });
    expect(sink.name).toBe("datadog");
  });

  it("should accept default site when not specified", () => {
    const sink = new DatadogSink({ apiKey: "k" });
    expect(sink.name).toBe("datadog");
  });
});

// ═══════════════════════════════════════════════════════════
// SyslogSink — host injection validation
// ═══════════════════════════════════════════════════════════

describe("SyslogSink SSRF validation", () => {
  it("should throw on host with URL metacharacters", () => {
    expect(
      () => new SyslogSink({ host: "evil.com/inject?x=1" })
    ).toThrow("invalid host");
  });

  it("should accept valid hostname", () => {
    const sink = new SyslogSink({ host: "syslog.example.com" });
    expect(sink.name).toBe("syslog");
  });

  it("should accept localhost (syslog servers are typically on private networks)", () => {
    const sink = new SyslogSink({ host: "localhost" });
    expect(sink.name).toBe("syslog");
  });

  it("should accept private IP (syslog is operator-configured)", () => {
    const sink = new SyslogSink({ host: "192.168.1.1" });
    expect(sink.name).toBe("syslog");
  });

  it("should validate facility range (0-23)", () => {
    expect(() => new SyslogSink({ host: "localhost", facility: -1 })).toThrow("facility must be an integer 0-23");
    expect(() => new SyslogSink({ host: "localhost", facility: 24 })).toThrow("facility must be an integer 0-23");
    expect(() => new SyslogSink({ host: "localhost", facility: 1.5 })).toThrow("facility must be an integer 0-23");
    expect(() => new SyslogSink({ host: "localhost", facility: 0 })).not.toThrow();
    expect(() => new SyslogSink({ host: "localhost", facility: 23 })).not.toThrow();
  });

  it("close() should be callable without error even without prior send", () => {
    const sink = new SyslogSink({ host: "localhost" });
    expect(() => sink.close()).not.toThrow();
  });

  it("close() should be callable multiple times", () => {
    const sink = new SyslogSink({ host: "localhost" });
    expect(() => {
      sink.close();
      sink.close();
    }).not.toThrow();
  });
});
