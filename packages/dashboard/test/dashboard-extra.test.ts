/**
 * Dashboard 补充测试 — EventStore, PolicyManager, SIEM sinks 边界场景
 */

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { generateEventId, type SecurityEvent, type AlertPayload } from "@carapace/core";
import { EventStore } from "../src/event-store.js";
import { PolicyManager, POLICY_TEMPLATES, type PolicyDefinition } from "../src/policy.js";
import { SplunkSink, ElasticSink, DatadogSink } from "../src/siem.js";

function makeEvent(overrides?: Partial<SecurityEvent>): SecurityEvent {
  return {
    id: generateEventId(),
    timestamp: Date.now(),
    category: "exec_danger",
    severity: "high",
    title: "Test",
    description: "Test",
    details: {},
    action: "alert",
    ruleName: "test-rule",
    toolName: "bash",
    ...overrides,
  };
}

function makePayload(overrides?: Partial<SecurityEvent>): AlertPayload {
  const event = makeEvent(overrides);
  return {
    event,
    summary: `[${event.severity.toUpperCase()}] ${event.title}`,
    actionTaken: event.action,
  };
}

// ═══════════════════════════════════════════════════════════
// EventStore extras
// ═══════════════════════════════════════════════════════════

describe("EventStore extras", () => {
  it("addBatch() adds multiple events", () => {
    const store = new EventStore();
    store.addBatch([makeEvent(), makeEvent(), makeEvent()]);
    expect(store.size).toBe(3);
  });

  it("query() with ruleName filter", () => {
    const store = new EventStore();
    store.add(makeEvent({ ruleName: "rule-a" }));
    store.add(makeEvent({ ruleName: "rule-b" }));
    store.add(makeEvent({ ruleName: "rule-a" }));

    const results = store.query({ ruleName: "rule-a" });
    expect(results).toHaveLength(2);
    expect(results.every((e) => e.ruleName === "rule-a")).toBe(true);
  });

  it("query() with sessionId filter", () => {
    const store = new EventStore();
    store.add(makeEvent({ sessionId: "s-1" }));
    store.add(makeEvent({ sessionId: "s-2" }));
    store.add(makeEvent({ sessionId: "s-1" }));

    const results = store.query({ sessionId: "s-1" });
    expect(results).toHaveLength(2);
  });

  it("query() with skillName filter", () => {
    const store = new EventStore();
    store.add(makeEvent({ skillName: "skill-x" }));
    store.add(makeEvent({ skillName: "skill-y" }));
    store.add(makeEvent({ skillName: "skill-x" }));

    const results = store.query({ skillName: "skill-x" });
    expect(results).toHaveLength(2);
  });

  it("query() with until filter", () => {
    const store = new EventStore();
    const now = Date.now();
    store.add(makeEvent({ timestamp: now - 5000 }));
    store.add(makeEvent({ timestamp: now - 3000 }));
    store.add(makeEvent({ timestamp: now - 1000 }));

    const results = store.query({ until: now - 2000 });
    expect(results).toHaveLength(2);
  });

  it("query() with combined filters (severity + category)", () => {
    const store = new EventStore();
    store.add(makeEvent({ severity: "high", category: "exec_danger" }));
    store.add(makeEvent({ severity: "low", category: "exec_danger" }));
    store.add(makeEvent({ severity: "high", category: "path_violation" }));

    const results = store.query({ severity: "high", category: "exec_danger" });
    expect(results).toHaveLength(1);
  });

  it("getStats() with since parameter", () => {
    const store = new EventStore();
    const now = Date.now();
    store.add(makeEvent({ timestamp: now - 10000 }));
    store.add(makeEvent({ timestamp: now - 5000 }));
    store.add(makeEvent({ timestamp: now - 1000 }));

    const stats = store.getStats(now - 6000);
    expect(stats.total).toBe(2);
  });

  it("getStats() on empty store", () => {
    const store = new EventStore();
    const stats = store.getStats();
    expect(stats.total).toBe(0);
    expect(stats.timeRange).toBeNull();
  });

  it("getStats() byRule and byCategory counts", () => {
    const store = new EventStore();
    store.add(makeEvent({ ruleName: "rule-1", category: "exec_danger" }));
    store.add(makeEvent({ ruleName: "rule-2", category: "exec_danger" }));
    store.add(makeEvent({ ruleName: "rule-1", category: "path_violation" }));

    const stats = store.getStats();
    expect(stats.byRule["rule-1"]).toBe(2);
    expect(stats.byCategory["exec_danger"]).toBe(2);
    expect(stats.byCategory["path_violation"]).toBe(1);
  });

  it("timeSeries() on empty store returns []", () => {
    const store = new EventStore();
    const series = store.timeSeries(1000);
    expect(series).toEqual([]);
  });

  it("timeSeries() with since parameter", () => {
    const store = new EventStore();
    const now = Date.now();
    store.add(makeEvent({ timestamp: now - 10000 }));
    store.add(makeEvent({ timestamp: now - 5000 }));
    store.add(makeEvent({ timestamp: now - 1000 }));

    const series = store.timeSeries(5000, now - 6000);
    expect(series.length).toBeGreaterThan(0);
    // should only contain events from last 6 seconds
    const totalCount = series.reduce((sum, b) => sum + b.count, 0);
    expect(totalCount).toBe(2);
  });

  it("timeSeries() with different bucket sizes", () => {
    const store = new EventStore();
    const now = Date.now();
    // Spread events over 10 seconds
    for (let i = 0; i < 10; i++) {
      store.add(makeEvent({ timestamp: now - i * 1000 }));
    }

    const smallBuckets = store.timeSeries(2000);  // 2s buckets
    const largeBuckets = store.timeSeries(10000);  // 10s buckets

    expect(smallBuckets.length).toBeGreaterThanOrEqual(largeBuckets.length);
  });
});

// ═══════════════════════════════════════════════════════════
// PolicyManager extras
// ═══════════════════════════════════════════════════════════

describe("PolicyManager extras", () => {
  it("removePolicy clears activePolicy if it's the removed one", () => {
    const pm = new PolicyManager();
    pm.addPolicy({
      name: "to-remove",
      description: "Will be removed",
      createdAt: Date.now(),
      updatedAt: Date.now(),
      config: {},
    });
    pm.setActivePolicy("to-remove");
    expect(pm.getActivePolicyName()).toBe("to-remove");

    pm.removePolicy("to-remove");
    expect(pm.getActivePolicyName()).toBeNull();
  });

  it("resolveActivePolicy when no active policy returns null", () => {
    const pm = new PolicyManager();
    expect(pm.resolveActivePolicy()).toBeNull();
  });

  it("resolveActivePolicy with active policy returns resolved", () => {
    const pm = new PolicyManager();
    pm.addPolicy({
      name: "active-one",
      description: "Active",
      createdAt: Date.now(),
      updatedAt: Date.now(),
      config: { blockOnCritical: true },
    });
    pm.setActivePolicy("active-one");

    const resolved = pm.resolveActivePolicy();
    expect(resolved).not.toBeNull();
    expect(resolved!.name).toBe("active-one");
    expect(resolved!.config.blockOnCritical).toBe(true);
  });

  it("resolvePolicy on non-existent policy throws", () => {
    const pm = new PolicyManager();
    expect(() => pm.resolvePolicy("nope")).toThrow();
  });

  it("Policy with nested inheritance (3 levels)", () => {
    const pm = new PolicyManager();
    pm.addPolicy({
      name: "grandparent",
      description: "GP",
      createdAt: 0,
      updatedAt: 0,
      config: { debug: true },
    });
    pm.addPolicy({
      name: "parent",
      description: "P",
      extends: "grandparent",
      createdAt: 0,
      updatedAt: 0,
      config: { blockOnCritical: true },
    });
    pm.addPolicy({
      name: "child",
      description: "C",
      extends: "parent",
      createdAt: 0,
      updatedAt: 0,
      config: { maxToolCallsPerMinute: 30 },
    });

    const resolved = pm.resolvePolicy("child");
    expect(resolved.config.debug).toBe(true);  // from grandparent
    expect(resolved.config.blockOnCritical).toBe(true);  // from parent
    expect(resolved.config.maxToolCallsPerMinute).toBe(30);  // from child
  });

  it("Import with activePolicy that doesn't exist in imported data", () => {
    const pm = new PolicyManager();
    const json = JSON.stringify({
      version: "1.0",
      exportedAt: new Date().toISOString(),
      activePolicy: "non-existent",
      policies: [
        { name: "only-policy", description: "X", createdAt: 0, updatedAt: 0, config: {} },
      ],
    });

    pm.importPolicies(json);
    // activePolicy should not be set since "non-existent" doesn't exist
    expect(pm.getActivePolicyName()).toBeNull();
    expect(pm.size).toBe(1);
  });

  it("Policy templates have correct structure", () => {
    expect(POLICY_TEMPLATES.permissive.name).toBe("permissive");
    expect(POLICY_TEMPLATES.standard.name).toBe("standard");
    expect(POLICY_TEMPLATES.strict.name).toBe("strict");
    expect(POLICY_TEMPLATES.strict.overrides?.forceBlock).toContain("exec-guard");
  });

  it("Export/import round-trip preserves all data", () => {
    const pm = new PolicyManager();
    pm.addPolicy({
      name: "round-trip",
      description: "Round trip test",
      createdAt: 1000,
      updatedAt: 2000,
      config: { blockOnCritical: true, debug: true },
      overrides: { forceBlock: ["exec-guard"] },
    });
    pm.setActivePolicy("round-trip");

    const json = pm.exportPolicies();
    const pm2 = new PolicyManager();
    pm2.importPolicies(json);

    expect(pm2.getActivePolicyName()).toBe("round-trip");
    const p = pm2.getPolicy("round-trip")!;
    expect(p.config.blockOnCritical).toBe(true);
    expect(p.overrides?.forceBlock).toContain("exec-guard");
  });

  it("updatedAt is set on addPolicy", () => {
    const pm = new PolicyManager();
    const before = Date.now();
    pm.addPolicy({
      name: "ts-test",
      description: "Timestamp test",
      createdAt: 0,
      updatedAt: 0,
      config: {},
    });
    const after = Date.now();

    const p = pm.getPolicy("ts-test")!;
    expect(p.updatedAt).toBeGreaterThanOrEqual(before);
    expect(p.updatedAt).toBeLessThanOrEqual(after);
  });
});

// ═══════════════════════════════════════════════════════════
// SIEM Sinks extras (mocking global fetch)
// ═══════════════════════════════════════════════════════════

describe("SIEM Sinks extras", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("SplunkSink.send() calls fetch with correct auth header", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("ok", { status: 200 }));
    globalThis.fetch = fetchMock;

    const sink = new SplunkSink({
      endpoint: "https://splunk.example.com:8088/services/collector/event",
      token: "my-token",
      index: "test-index",
    });

    await sink.send(makePayload());

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toContain("splunk.example.com");
    expect(options.headers.Authorization).toBe("Splunk my-token");
    const body = JSON.parse(options.body);
    expect(body.index).toBe("test-index");
  });

  it("ElasticSink.send() with apiKey auth header", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("ok", { status: 201 }));
    globalThis.fetch = fetchMock;

    const sink = new ElasticSink({
      endpoint: "https://elastic.example.com:9200",
      apiKey: "my-api-key",
      index: "my-index",
    });

    await sink.send(makePayload());

    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toContain("my-index/_doc");
    expect(options.headers.Authorization).toBe("ApiKey my-api-key");
  });

  it("ElasticSink.send() with basic auth", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("ok", { status: 201 }));
    globalThis.fetch = fetchMock;

    const sink = new ElasticSink({
      endpoint: "https://elastic.example.com:9200",
      username: "admin",
      password: "secret",
    });

    await sink.send(makePayload());

    expect(fetchMock).toHaveBeenCalledOnce();
    const [, options] = fetchMock.mock.calls[0];
    const encoded = Buffer.from("admin:secret").toString("base64");
    expect(options.headers.Authorization).toBe(`Basic ${encoded}`);
  });

  it("ElasticSink.send() with default index name", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("ok", { status: 201 }));
    globalThis.fetch = fetchMock;

    const sink = new ElasticSink({
      endpoint: "https://elastic.example.com:9200",
    });

    await sink.send(makePayload());

    const [url] = fetchMock.mock.calls[0];
    expect(url).toContain("carapace-events/_doc");
  });

  it("DatadogSink severity mapping via send", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("ok", { status: 202 }));
    globalThis.fetch = fetchMock;

    const sink = new DatadogSink({ apiKey: "dd-key" });

    for (const sev of ["low", "medium", "high", "critical"] as const) {
      await sink.send(makePayload({ severity: sev }));
    }

    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it("DatadogSink with custom tags and service", async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response("ok", { status: 202 }));
    globalThis.fetch = fetchMock;

    const sink = new DatadogSink({
      apiKey: "dd-key",
      tags: ["env:test", "team:security"],
      service: "my-service",
    });

    await sink.send(makePayload());

    expect(fetchMock).toHaveBeenCalledOnce();
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body[0].ddtags).toContain("env:test");
    expect(body[0].service).toBe("my-service");
  });
});
