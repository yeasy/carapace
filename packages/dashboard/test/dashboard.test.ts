/**
 * Dashboard 包测试 — EventStore, PolicyManager, SIEM sinks, DashboardServer
 */

import { describe, it, expect, afterEach } from "vitest";
import { generateEventId, type SecurityEvent } from "@carapace/core";
import { EventStore } from "../src/event-store.js";
import {
  PolicyManager,
  POLICY_TEMPLATES,
  type PolicyDefinition,
} from "../src/policy.js";
import { SplunkSink, ElasticSink, DatadogSink, SyslogSink } from "../src/siem.js";
import { DashboardServer } from "../src/server.js";

// ── 辅助函数 ──

function makeEvent(overrides?: Partial<SecurityEvent>): SecurityEvent {
  return {
    id: generateEventId(),
    timestamp: Date.now(),
    category: "exec_danger",
    severity: "high",
    title: "Test event",
    description: "Test description",
    details: {},
    action: "alert",
    ruleName: "test-rule",
    toolName: "bash",
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════════
// EventStore
// ═══════════════════════════════════════════════════════════

describe("EventStore", () => {
  it("添加和查询事件", () => {
    const store = new EventStore();
    const now = Date.now();
    store.add(makeEvent({ title: "event-1", timestamp: now }));
    store.add(makeEvent({ title: "event-2", timestamp: now + 1000 }));
    expect(store.size).toBe(2);

    const events = store.query();
    expect(events).toHaveLength(2);
    // 倒序排列（新的在前）
    expect(events[0].title).toBe("event-2");
  });

  it("按 category 过滤", () => {
    const store = new EventStore();
    store.add(makeEvent({ category: "exec_danger" }));
    store.add(makeEvent({ category: "path_violation" }));
    store.add(makeEvent({ category: "exec_danger" }));

    const results = store.query({ category: "exec_danger" });
    expect(results).toHaveLength(2);
  });

  it("按 severity 过滤", () => {
    const store = new EventStore();
    store.add(makeEvent({ severity: "critical" }));
    store.add(makeEvent({ severity: "low" }));

    const results = store.query({ severity: "critical" });
    expect(results).toHaveLength(1);
  });

  it("时间范围过滤", () => {
    const store = new EventStore();
    const now = Date.now();
    store.add(makeEvent({ timestamp: now - 60000 }));
    store.add(makeEvent({ timestamp: now - 30000 }));
    store.add(makeEvent({ timestamp: now }));

    const results = store.query({ since: now - 40000 });
    expect(results).toHaveLength(2);
  });

  it("分页", () => {
    const store = new EventStore();
    for (let i = 0; i < 20; i++) {
      store.add(makeEvent({ title: `event-${i}`, timestamp: Date.now() + i }));
    }

    const page1 = store.query({ limit: 5, offset: 0 });
    expect(page1).toHaveLength(5);
    const page2 = store.query({ limit: 5, offset: 5 });
    expect(page2).toHaveLength(5);
    expect(page1[0].title).not.toBe(page2[0].title);
  });

  it("统计信息", () => {
    const store = new EventStore();
    store.add(makeEvent({ severity: "critical", action: "blocked" }));
    store.add(makeEvent({ severity: "high", action: "alert" }));
    store.add(makeEvent({ severity: "high", action: "alert" }));

    const stats = store.getStats();
    expect(stats.total).toBe(3);
    expect(stats.bySeverity.critical).toBe(1);
    expect(stats.bySeverity.high).toBe(2);
    expect(stats.blockedCount).toBe(1);
    expect(stats.alertCount).toBe(2);
    expect(stats.timeRange).not.toBeNull();
  });

  it("时间序列聚合", () => {
    const store = new EventStore();
    // 对齐到分钟边界+5s，确保 3 个事件在同一个桶
    const base = Math.floor(Date.now() / 60000) * 60000 + 5000;
    store.add(makeEvent({ timestamp: base }));
    store.add(makeEvent({ timestamp: base + 1000 }));
    store.add(makeEvent({ timestamp: base + 2000, action: "blocked" }));
    // 下一分钟
    store.add(makeEvent({ timestamp: base + 61000 }));

    const ts = store.timeSeries(60000);
    expect(ts.length).toBe(2);
    expect(ts[0].count).toBe(3);
    expect(ts[0].blocked).toBe(1);
  });

  it("最大事件数限制", () => {
    const store = new EventStore(5);
    // With headroom batching, eviction triggers at maxEvents + headroom
    // For small stores (headroom min=100), 10 items won't trigger eviction
    for (let i = 0; i < 10; i++) {
      store.add(makeEvent({ title: `event-${i}` }));
    }
    expect(store.size).toBeLessThanOrEqual(10);

    // Test with enough items to trigger eviction (maxEvents=5, headroom=100)
    for (let i = 10; i < 200; i++) {
      store.add(makeEvent({ title: `event-${i}` }));
    }
    expect(store.size).toBeLessThanOrEqual(105);
    expect(store.size).toBeGreaterThanOrEqual(5);
  });

  it("clear 清空", () => {
    const store = new EventStore();
    store.add(makeEvent());
    store.clear();
    expect(store.size).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════
// PolicyManager
// ═══════════════════════════════════════════════════════════

describe("PolicyManager", () => {
  it("添加和获取策略", () => {
    const pm = new PolicyManager();
    pm.addPolicy({
      name: "test-policy",
      description: "Test",
      createdAt: Date.now(),
      updatedAt: Date.now(),
      config: { blockOnCritical: true },
    });
    expect(pm.size).toBe(1);
    expect(pm.getPolicy("test-policy")).toBeDefined();
  });

  it("列出所有策略", () => {
    const pm = new PolicyManager();
    pm.addPolicy({ name: "a", description: "A", createdAt: 0, updatedAt: 0, config: {} });
    pm.addPolicy({ name: "b", description: "B", createdAt: 0, updatedAt: 0, config: {} });
    expect(pm.listPolicies()).toHaveLength(2);
  });

  it("删除策略", () => {
    const pm = new PolicyManager();
    pm.addPolicy({ name: "x", description: "X", createdAt: 0, updatedAt: 0, config: {} });
    expect(pm.removePolicy("x")).toBe(true);
    expect(pm.size).toBe(0);
    expect(pm.removePolicy("nonexistent")).toBe(false);
  });

  it("设置和获取活跃策略", () => {
    const pm = new PolicyManager();
    pm.addPolicy({ name: "prod", description: "Production", createdAt: 0, updatedAt: 0, config: {} });
    pm.setActivePolicy("prod");
    expect(pm.getActivePolicyName()).toBe("prod");
  });

  it("设置不存在的策略抛错", () => {
    const pm = new PolicyManager();
    expect(() => pm.setActivePolicy("nope")).toThrow();
  });

  it("策略继承", () => {
    const pm = new PolicyManager();
    pm.addPolicy({
      name: "base",
      description: "Base policy",
      createdAt: 0,
      updatedAt: 0,
      config: { blockOnCritical: false, debug: true },
    });
    pm.addPolicy({
      name: "child",
      description: "Child policy",
      extends: "base",
      createdAt: 0,
      updatedAt: 0,
      config: { blockOnCritical: true }, // 覆盖父级
    });

    const resolved = pm.resolvePolicy("child");
    expect(resolved.config.blockOnCritical).toBe(true); // 子级覆盖
    expect(resolved.config.debug).toBe(true); // 从父级继承
  });

  it("循环继承检测", () => {
    const pm = new PolicyManager();
    pm.addPolicy({ name: "a", extends: "b", description: "", createdAt: 0, updatedAt: 0, config: {} });
    pm.addPolicy({ name: "b", extends: "a", description: "", createdAt: 0, updatedAt: 0, config: {} });
    expect(() => pm.resolvePolicy("a")).toThrow("Circular");
  });

  it("overrides 合并", () => {
    const pm = new PolicyManager();
    pm.addPolicy({
      name: "strict",
      description: "Strict",
      createdAt: 0,
      updatedAt: 0,
      config: {},
      overrides: {
        forceBlock: ["exec-guard", "path-guard"],
        disabledRules: ["rate-limiter"],
        additionalTrustedSkills: ["deploy-bot"],
      },
    });

    const resolved = pm.resolvePolicy("strict");
    expect(resolved.forceBlock).toContain("exec-guard");
    expect(resolved.disabledRules).toContain("rate-limiter");
    expect(resolved.trustedSkills).toContain("deploy-bot");
  });

  it("导出和导入", () => {
    const pm = new PolicyManager();
    pm.addPolicy({ name: "export-test", description: "Test", createdAt: 0, updatedAt: 0, config: { blockOnCritical: true } });
    pm.setActivePolicy("export-test");

    const json = pm.exportPolicies();
    expect(json).toContain("export-test");

    const pm2 = new PolicyManager();
    const count = pm2.importPolicies(json);
    expect(count).toBe(1);
    expect(pm2.getActivePolicyName()).toBe("export-test");
    expect(pm2.getPolicy("export-test")!.config.blockOnCritical).toBe(true);
  });

  it("预定义模板", () => {
    expect(POLICY_TEMPLATES.permissive.config.blockOnCritical).toBe(false);
    expect(POLICY_TEMPLATES.standard.config.blockOnCritical).toBe(true);
    expect(POLICY_TEMPLATES.strict.overrides?.forceBlock?.length).toBeGreaterThan(0);
  });
});

// ═══════════════════════════════════════════════════════════
// SIEM Sinks (构造测试)
// ═══════════════════════════════════════════════════════════

describe("SIEM Sinks", () => {
  it("SplunkSink 构造", () => {
    const sink = new SplunkSink({ endpoint: "https://splunk.local:8088/services/collector/event", token: "test-token" });
    expect(sink.name).toBe("splunk");
  });

  it("ElasticSink 构造", () => {
    const sink = new ElasticSink({ endpoint: "https://elastic.local:9200" });
    expect(sink.name).toBe("elastic");
  });

  it("DatadogSink 构造", () => {
    const sink = new DatadogSink({ apiKey: "test-key" });
    expect(sink.name).toBe("datadog");
  });

  it("SyslogSink 构造", () => {
    const sink = new SyslogSink({ host: "syslog.local" });
    expect(sink.name).toBe("syslog");
  });
});

// ═══════════════════════════════════════════════════════════
// DashboardServer
// ═══════════════════════════════════════════════════════════

describe("DashboardServer", () => {
  let server: DashboardServer | null = null;

  afterEach(async () => {
    if (server) {
      await server.stop();
      server = null;
    }
  });

  it("创建实例", () => {
    server = new DashboardServer();
    expect(server.getStore()).toBeInstanceOf(EventStore);
    expect(server.getPolicyManager()).toBeInstanceOf(PolicyManager);
  });

  it("createSink 返回 AlertSink", async () => {
    server = new DashboardServer();
    const sink = server.createSink();
    expect(sink.name).toBe("dashboard");

    await sink.send({
      event: makeEvent({ title: "sink-test" }),
      summary: "[HIGH] sink-test",
      actionTaken: "alert",
    });
    expect(server.getStore().size).toBe(1);
  });

  it("启动和停止", async () => {
    server = new DashboardServer({ port: 0 });
    await server.start();
    await server.stop();
    server = null;
  });

  it("HTTP API 可访问", async () => {
    server = new DashboardServer({ port: 0 });
    await server.start();
    const port = server.getPort();

    // 添加测试事件
    server.getStore().add(makeEvent({ title: "api-test" }));

    const healthRes = await fetch(`http://127.0.0.1:${port}/api/health`);
    expect(healthRes.status).toBe(200);
    const health = await healthRes.json();
    expect(health.status).toBe("ok");

    const statsRes = await fetch(`http://127.0.0.1:${port}/api/stats`);
    expect(statsRes.status).toBe(200);
    const stats = (await statsRes.json()) as { total: number };
    expect(stats.total).toBe(1);

    const eventsRes = await fetch(`http://127.0.0.1:${port}/api/events`);
    expect(eventsRes.status).toBe(200);
    const events = (await eventsRes.json()) as any[];
    expect(events).toHaveLength(1);
    expect(events[0].title).toBe("api-test");

    // Dashboard HTML
    const dashRes = await fetch(`http://127.0.0.1:${port}/`);
    expect(dashRes.status).toBe(200);
    const html = await dashRes.text();
    expect(html).toContain("Carapace Dashboard");
  });

  it("Policy API", async () => {
    server = new DashboardServer({ port: 0 });
    await server.start();
    const port = server.getPort();

    // 添加策略
    const addRes = await fetch(`http://127.0.0.1:${port}/api/policies`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: "test-policy",
        description: "Test",
        config: { blockOnCritical: true },
      }),
    });
    expect(addRes.status).toBe(201);

    // 列出策略
    const listRes = await fetch(`http://127.0.0.1:${port}/api/policies`);
    const policies = (await listRes.json()) as any[];
    expect(policies).toHaveLength(1);

    // 设置活跃策略
    const activeRes = await fetch(
      `http://127.0.0.1:${port}/api/policies/active/test-policy`,
      { method: "PUT" }
    );
    expect(activeRes.status).toBe(200);

    // 获取活跃策略
    const getActiveRes = await fetch(`http://127.0.0.1:${port}/api/policies/active`);
    const active = (await getActiveRes.json()) as { name: string };
    expect(active.name).toBe("test-policy");
  });

  it("拒绝缺少 name 字段的策略", async () => {
    server = new DashboardServer({ port: 0 });
    await server.start();
    const port = server.getPort();

    const res = await fetch(`http://127.0.0.1:${port}/api/policies`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ description: "no name field" }),
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("name");
  });

  it("事件查询忽略无效 severity 值", async () => {
    server = new DashboardServer({ port: 0 });
    await server.start();
    const port = server.getPort();

    const sink = server.createSink();
    await sink.send({ event: makeEvent({ severity: "high" }), timestamp: Date.now() });

    const res = await fetch(`http://127.0.0.1:${port}/api/events?severity=invalid`);
    expect(res.status).toBe(200);
    const events = (await res.json()) as unknown[];
    expect(events).toHaveLength(1);
  });

  it("事件查询忽略负数 limit 和 offset", async () => {
    server = new DashboardServer({ port: 0 });
    await server.start();
    const port = server.getPort();

    const sink = server.createSink();
    await sink.send({ event: makeEvent(), timestamp: Date.now() });

    const res = await fetch(`http://127.0.0.1:${port}/api/events?limit=-5&offset=-1`);
    expect(res.status).toBe(200);
    const events = (await res.json()) as unknown[];
    expect(events).toHaveLength(1);
  });
});
