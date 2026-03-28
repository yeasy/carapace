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
});
