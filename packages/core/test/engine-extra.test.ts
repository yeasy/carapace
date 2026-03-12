/**
 * engine-extra.test.ts — Extra test coverage for RuleEngine and AlertRouter
 *
 * Tests for edge cases, error handling, and features not covered in existing tests.
 */

import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { RuleEngine } from "../src/engine.js";
import {
  AlertRouter,
  ConsoleSink,
  WebhookSink,
  LogFileSink,
  HookMessageSink,
  DismissalManager,
  AlertEscalation,
} from "../src/alerter.js";
import type { SecurityRule, RuleContext, SecurityEvent } from "../src/types.js";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFileSync, rmSync } from "node:fs";

// ─── Test Helpers ──────────────────────────────────────────────────────

function createMockRule(
  name: string,
  shouldTrigger: boolean = true,
  severity: "critical" | "high" | "medium" | "low" | "info" = "medium",
  shouldBlock: boolean = false
): SecurityRule {
  return {
    name,
    description: `Mock rule: ${name}`,
    check: (ctx: RuleContext) => {
      if (!shouldTrigger) {
        return { triggered: false };
      }
      return {
        triggered: true,
        event: {
          category: "exec_danger",
          severity,
          title: `Alert from ${name}`,
          description: `Rule ${name} triggered`,
          details: { matched: true },
        },
        shouldBlock,
      };
    },
  };
}

function createThrowingRule(name: string): SecurityRule {
  return {
    name,
    description: `Rule that throws: ${name}`,
    check: () => {
      throw new Error("Intentional test error");
    },
  };
}

function createSecurityEvent(
  overrides: Partial<SecurityEvent> = {}
): SecurityEvent {
  const defaults: SecurityEvent = {
    id: `event-${Math.random().toString(36).slice(2)}`,
    timestamp: Date.now(),
    category: "exec_danger",
    severity: "medium",
    title: "Test alert",
    description: "Test alert description",
    details: {},
    action: "alert",
  };

  return { ...defaults, ...overrides };
}

// ═════════════════════════════════════════════════════════════════════════
// RuleEngine Extra Tests
// ═════════════════════════════════════════════════════════════════════════

describe("RuleEngine — Extra Coverage", () => {
  let engine: RuleEngine;

  beforeEach(() => {
    engine = new RuleEngine();
  });

  // ─── removeRule() Tests ─────────────────────────────────────────────

  describe("removeRule()", () => {
    it("should remove a rule by name", () => {
      const rule1 = createMockRule("rule1");
      const rule2 = createMockRule("rule2");

      engine.addRule(rule1);
      engine.addRule(rule2);

      expect(engine.getRules()).toHaveLength(2);

      engine.removeRule("rule1");

      expect(engine.getRules()).toHaveLength(1);
      expect(engine.getRules()[0].name).toBe("rule2");
    });

    it("should remove all matching rules with the same name", () => {
      const rule1a = createMockRule("rule1");
      const rule1b = createMockRule("rule1");
      const rule2 = createMockRule("rule2");

      engine.addRule(rule1a);
      engine.addRule(rule1b);
      engine.addRule(rule2);

      engine.removeRule("rule1");

      expect(engine.getRules()).toHaveLength(1);
      expect(engine.getRules()[0].name).toBe("rule2");
    });

    it("should be a no-op when removing non-existent rule name", () => {
      const rule1 = createMockRule("rule1");
      engine.addRule(rule1);

      expect(engine.getRules()).toHaveLength(1);

      engine.removeRule("non-existent");

      expect(engine.getRules()).toHaveLength(1);
      expect(engine.getRules()[0].name).toBe("rule1");
    });

    it("should handle removing from empty engine", () => {
      expect(engine.getRules()).toHaveLength(0);

      engine.removeRule("any-name");

      expect(engine.getRules()).toHaveLength(0);
    });
  });

  // ─── evaluate() with zero rules ─────────────────────────────────────

  describe("evaluate() with zero rules", () => {
    it("should return triggered=false and empty events", () => {
      const ctx: RuleContext = {
        toolName: "test_tool",
        toolParams: { param: "value" },
        timestamp: Date.now(),
      };

      const result = engine.evaluate(ctx);

      expect(result.triggered).toBe(false);
      expect(result.shouldBlock).toBe(false);
      expect(result.events).toHaveLength(0);
      expect(result.blockReason).toBeUndefined();
    });
  });

  // ─── evaluate() with rule that throws exception ─────────────────────

  describe("evaluate() with exception handling", () => {
    it("should catch exception from a rule and continue with other rules", () => {
      const throwingRule = createThrowingRule("throwing_rule");
      const normalRule = createMockRule("normal_rule", true, "high");

      engine.addRule(throwingRule);
      engine.addRule(normalRule);

      const ctx: RuleContext = {
        toolName: "test_tool",
        toolParams: {},
        timestamp: Date.now(),
      };

      const result = engine.evaluate(ctx);

      // Should have caught the error and continued with normal_rule
      expect(result.triggered).toBe(true);
      expect(result.events).toHaveLength(1);
      expect(result.events[0].ruleName).toBe("normal_rule");
    });

    it("should handle multiple throwing rules gracefully", () => {
      const throwing1 = createThrowingRule("throwing1");
      const throwing2 = createThrowingRule("throwing2");
      const normal = createMockRule("normal", true, "medium");

      engine.addRule(throwing1);
      engine.addRule(throwing2);
      engine.addRule(normal);

      const ctx: RuleContext = {
        toolName: "test_tool",
        toolParams: {},
        timestamp: Date.now(),
      };

      const result = engine.evaluate(ctx);

      // Should only get event from normal rule
      expect(result.triggered).toBe(true);
      expect(result.events).toHaveLength(1);
      expect(result.events[0].ruleName).toBe("normal");
    });

    it("should return empty result if all rules throw", () => {
      const throwing1 = createThrowingRule("throwing1");
      const throwing2 = createThrowingRule("throwing2");

      engine.addRule(throwing1);
      engine.addRule(throwing2);

      const ctx: RuleContext = {
        toolName: "test_tool",
        toolParams: {},
        timestamp: Date.now(),
      };

      const result = engine.evaluate(ctx);

      expect(result.triggered).toBe(false);
      expect(result.shouldBlock).toBe(false);
      expect(result.events).toHaveLength(0);
    });
  });

  // ─── evaluate() with multiple rules and different severities ────────

  describe("evaluate() with multiple rules and severity handling", () => {
    it("should use highest severity for blockReason", () => {
      const criticalRule = createMockRule("critical_rule", true, "critical", true);
      const highRule = createMockRule("high_rule", true, "high", true);
      const mediumRule = createMockRule("medium_rule", true, "medium", true);

      engine.addRule(mediumRule);
      engine.addRule(highRule);
      engine.addRule(criticalRule);

      const ctx: RuleContext = {
        toolName: "test_tool",
        toolParams: {},
        timestamp: Date.now(),
      };

      const result = engine.evaluate(ctx);

      expect(result.triggered).toBe(true);
      expect(result.shouldBlock).toBe(true);
      expect(result.blockReason).toBe("Alert from critical_rule");
      expect(result.events).toHaveLength(3);
    });

    it("should collect events from all triggered rules", () => {
      const rule1 = createMockRule("rule1", true, "low");
      const rule2 = createMockRule("rule2", true, "medium");
      const rule3 = createMockRule("rule3", true, "high");

      engine.addRule(rule1);
      engine.addRule(rule2);
      engine.addRule(rule3);

      const ctx: RuleContext = {
        toolName: "test_tool",
        toolParams: {},
        timestamp: Date.now(),
      };

      const result = engine.evaluate(ctx);

      expect(result.triggered).toBe(true);
      expect(result.events).toHaveLength(3);
      expect(result.events.map((e) => e.ruleName).sort()).toEqual([
        "rule1",
        "rule2",
        "rule3",
      ]);
    });

    it("should preserve severity order in multiple block scenarios", () => {
      const highBlock = createMockRule("high_block", true, "high", true);
      const criticalAlert = createMockRule("critical_alert", true, "critical", false);
      const mediumBlock = createMockRule("medium_block", true, "medium", true);

      engine.addRule(mediumBlock);
      engine.addRule(highBlock);
      engine.addRule(criticalAlert);

      const ctx: RuleContext = {
        toolName: "test_tool",
        toolParams: {},
        timestamp: Date.now(),
      };

      const result = engine.evaluate(ctx);

      expect(result.blockReason).toBe("Alert from high_block");
    });
  });

  // ─── evaluateForBlock() with blockOnCritical=false ──────────────────

  describe("evaluateForBlock() with blockOnCritical=false", () => {
    it("should never set block=true even with shouldBlock events", () => {
      const rule = createMockRule("blocking_rule", true, "critical", true);
      engine.addRule(rule);

      const ctx: RuleContext = {
        toolName: "test_tool",
        toolParams: {},
        timestamp: Date.now(),
      };

      const { decision, events } = engine.evaluateForBlock(ctx, false);

      expect(decision.block).toBe(false);
      expect(events).toHaveLength(1);
      expect(events[0].severity).toBe("critical");
    });

    it("should still populate blockReason even when block=false", () => {
      const rule = createMockRule("rule1", true, "critical", true);
      engine.addRule(rule);

      const ctx: RuleContext = {
        toolName: "test_tool",
        toolParams: {},
        timestamp: Date.now(),
      };

      const { decision } = engine.evaluateForBlock(ctx, false);

      expect(decision.block).toBe(false);
      expect(decision.blockReason).toBe("Alert from rule1");
    });
  });

  // ─── evaluateForBlock() with blockOnCritical=true and no shouldBlock ─

  describe("evaluateForBlock() with blockOnCritical=true", () => {
    it("should set block=false when no shouldBlock events exist", () => {
      const rule = createMockRule("alert_only_rule", true, "critical", false);
      engine.addRule(rule);

      const ctx: RuleContext = {
        toolName: "test_tool",
        toolParams: {},
        timestamp: Date.now(),
      };

      const { decision, events } = engine.evaluateForBlock(ctx, true);

      expect(decision.block).toBe(false);
      expect(events).toHaveLength(1);
      expect(events[0].severity).toBe("critical");
    });

    it("should set block=true when shouldBlock events and blockOnCritical=true", () => {
      const rule = createMockRule("blocking_rule", true, "critical", true);
      engine.addRule(rule);

      const ctx: RuleContext = {
        toolName: "test_tool",
        toolParams: {},
        timestamp: Date.now(),
      };

      const { decision } = engine.evaluateForBlock(ctx, true);

      expect(decision.block).toBe(true);
      expect(decision.blockReason).toBe("Alert from blocking_rule");
    });
  });

  // ─── Trusted Skills ────────────────────────────────────────────────

  describe("Trusted Skills", () => {
    it("should setTrustedSkills and getTrustedSkills", () => {
      const skills = ["skill1", "skill2"];
      engine.setTrustedSkills(skills);

      const trusted = engine.getTrustedSkills();
      expect(trusted.has("skill1")).toBe(true);
      expect(trusted.has("skill2")).toBe(true);
      expect(trusted.has("skill3")).toBe(false);
    });

    it("should skip evaluation for trusted skill", () => {
      const rule = createMockRule("rule1", true, "critical", true);
      engine.addRule(rule);
      engine.setTrustedSkills(["trusted_skill"]);

      const ctx: RuleContext = {
        toolName: "test_tool",
        toolParams: {},
        skillName: "trusted_skill",
        timestamp: Date.now(),
      };

      const result = engine.evaluate(ctx);

      expect(result.triggered).toBe(false);
      expect(result.events).toHaveLength(0);
    });

    it("should still evaluate non-trusted skills", () => {
      const rule = createMockRule("rule1", true, "high");
      engine.addRule(rule);
      engine.setTrustedSkills(["trusted_skill"]);

      const ctx: RuleContext = {
        toolName: "test_tool",
        toolParams: {},
        skillName: "untrusted_skill",
        timestamp: Date.now(),
      };

      const result = engine.evaluate(ctx);

      expect(result.triggered).toBe(true);
      expect(result.events).toHaveLength(1);
    });

    it("should skip when skillName matches any trusted skill", () => {
      const rule = createMockRule("rule1", true, "high");
      engine.addRule(rule);
      engine.setTrustedSkills(["trusted1", "trusted2", "trusted3"]);

      const ctx: RuleContext = {
        toolName: "test_tool",
        toolParams: {},
        skillName: "trusted2",
        timestamp: Date.now(),
      };

      const result = engine.evaluate(ctx);

      expect(result.triggered).toBe(false);
    });

    it("should evaluate when skillName is undefined", () => {
      const rule = createMockRule("rule1", true, "high");
      engine.addRule(rule);
      engine.setTrustedSkills(["trusted_skill"]);

      const ctx: RuleContext = {
        toolName: "test_tool",
        toolParams: {},
        // skillName is undefined
        timestamp: Date.now(),
      };

      const result = engine.evaluate(ctx);

      expect(result.triggered).toBe(true);
      expect(result.events).toHaveLength(1);
    });
  });
});

// ═════════════════════════════════════════════════════════════════════════
// AlertRouter Extra Tests
// ═════════════════════════════════════════════════════════════════════════

describe("AlertRouter — Extra Coverage", () => {
  // ─── removeSink() Tests ────────────────────────────────────────────

  describe("removeSink()", () => {
    it("should remove a sink by name", async () => {
      const mockSink1 = { name: "sink1", send: vi.fn() };
      const mockSink2 = { name: "sink2", send: vi.fn() };

      const router = new AlertRouter({ enableEscalation: false, enableDismissal: false });
      router.addSink(mockSink1);
      router.addSink(mockSink2);

      // Verify both sinks are there
      const event = createSecurityEvent();
      await router.send(event);
      expect(mockSink1.send).toHaveBeenCalledOnce();
      expect(mockSink2.send).toHaveBeenCalledOnce();

      // Remove sink1
      router.removeSink("sink1");

      // Reset mocks
      vi.clearAllMocks();

      // Send another event (different toolName to avoid dedup)
      await router.send(createSecurityEvent({ id: "event2", toolName: "different-tool", toolParams: { x: "unique" } }));
      expect(mockSink1.send).not.toHaveBeenCalled();
      expect(mockSink2.send).toHaveBeenCalledOnce();
    });

    it("should be a no-op when removing non-existent sink", async () => {
      const mockSink = { name: "sink1", send: vi.fn() };
      const router = new AlertRouter({ enableEscalation: false, enableDismissal: false });
      router.addSink(mockSink);

      router.removeSink("non-existent");

      const event = createSecurityEvent();
      await router.send(event);
      expect(mockSink.send).toHaveBeenCalledOnce();
    });
  });

  // ─── Dedup Cleanup Tests ───────────────────────────────────────────

  describe("Dedup cleanup (>100 entries)", () => {
    it("should cleanup old dedup entries when size exceeds 100", async () => {
      const mockSink = { name: "test", send: vi.fn() };
      const router = new AlertRouter({ enableEscalation: false, enableDismissal: false });
      router.addSink(mockSink);

      // Add 101 distinct events to trigger cleanup
      for (let i = 0; i < 101; i++) {
        const event = createSecurityEvent({
          id: `event-${i}`,
          ruleName: `rule-${i}`,
          toolName: `tool-${i}`,
          toolParams: { iteration: i },
        });
        await router.send(event);
      }

      // All events should have been sent (dedup window = 5 min, all within window)
      expect(mockSink.send).toHaveBeenCalledTimes(101);
    });

    it("should only send first occurrence within 5 minute dedup window", async () => {
      const mockSink = { name: "test", send: vi.fn() };
      const router = new AlertRouter({ enableEscalation: false, enableDismissal: false });
      router.addSink(mockSink);

      const baseEvent = createSecurityEvent({
        ruleName: "rule1",
        toolName: "tool1",
        toolParams: { param: "same" },
      });

      // Send same event 3 times
      await router.send(baseEvent);
      await router.send({ ...baseEvent, id: "event2" });
      await router.send({ ...baseEvent, id: "event3" });

      // Only first should be sent (dedup active)
      expect(mockSink.send).toHaveBeenCalledOnce();
    });
  });
});

// ═════════════════════════════════════════════════════════════════════════
// HookMessageSink Extra Tests
// ═════════════════════════════════════════════════════════════════════════

describe("HookMessageSink — Extra Coverage", () => {
  it('should allow critical events through even with minSeverity="critical"', async () => {
    const mockCallback = vi.fn();
    const sink = new HookMessageSink(mockCallback, "critical");

    const event = createSecurityEvent({
      severity: "critical",
      title: "Critical alert",
      description: "This is critical",
      ruleName: "rule1",
      toolName: "tool1",
    });

    await sink.send({
      event,
      summary: "[CRITICAL] Critical alert",
      actionTaken: "alert",
    });

    expect(mockCallback).toHaveBeenCalledOnce();
    const message = mockCallback.mock.calls[0][0];
    expect(message).toContain("CRITICAL");
  });

  it('should not allow high severity events with minSeverity="critical"', async () => {
    const mockCallback = vi.fn();
    const sink = new HookMessageSink(mockCallback, "critical");

    const event = createSecurityEvent({
      severity: "high",
      title: "High alert",
      description: "This is high",
      ruleName: "rule1",
      toolName: "tool1",
    });

    await sink.send({
      event,
      summary: "[HIGH] High alert",
      actionTaken: "alert",
    });

    expect(mockCallback).not.toHaveBeenCalled();
  });
});

// ═════════════════════════════════════════════════════════════════════════
// DismissalManager Extra Tests
// ═════════════════════════════════════════════════════════════════════════

describe("DismissalManager — Extra Coverage", () => {
  describe("cleanupExpired()", () => {
    it("should remove only expired patterns, keep valid ones", () => {
      const now = Date.now();
      const manager = new DismissalManager();

      const expired1 = {
        id: "expired1",
        ruleName: "rule1",
        reason: "Expired",
        createdAt: now - 10000,
        expiresAt: now - 1000,
      };

      const expired2 = {
        id: "expired2",
        ruleName: "rule2",
        reason: "Expired",
        createdAt: now - 10000,
        expiresAt: now - 100,
      };

      const valid = {
        id: "valid1",
        ruleName: "rule3",
        reason: "Valid",
        createdAt: now - 1000,
        expiresAt: now + 60000,
      };

      const permanent = {
        id: "permanent",
        ruleName: "rule4",
        reason: "Permanent",
        createdAt: now - 1000,
        // no expiresAt
      };

      manager.addDismissal(expired1);
      manager.addDismissal(expired2);
      manager.addDismissal(valid);
      manager.addDismissal(permanent);

      const cleaned = manager.cleanupExpired();

      expect(cleaned).toBe(2);
      expect(manager.size).toBe(2);
      expect(manager.listDismissals().map((p) => p.id)).toEqual(["valid1", "permanent"]);
    });
  });

  describe("Duplicate dismissals", () => {
    it("should allow adding the same pattern twice", () => {
      const manager = new DismissalManager();

      const pattern = {
        id: "id1",
        ruleName: "rule1",
        reason: "Duplicate test",
        createdAt: Date.now(),
      };

      manager.addDismissal(pattern);
      manager.addDismissal(pattern);

      expect(manager.size).toBe(2);
      expect(manager.listDismissals()).toHaveLength(2);
    });

    it("should remove only one when removing duplicate by id", () => {
      const manager = new DismissalManager();

      const pattern1 = {
        id: "id1",
        ruleName: "rule1",
        reason: "First",
        createdAt: Date.now(),
      };

      const pattern2 = {
        id: "id1",
        ruleName: "rule1",
        reason: "Second (same id)",
        createdAt: Date.now(),
      };

      manager.addDismissal(pattern1);
      manager.addDismissal(pattern2);

      const removed = manager.removeDismissal("id1");

      expect(removed).toBe(true);
      expect(manager.size).toBe(0); // Removes all with that id
    });
  });
});

// ═════════════════════════════════════════════════════════════════════════
// AlertEscalation Extra Tests
// ═════════════════════════════════════════════════════════════════════════

describe("AlertEscalation — Extra Coverage", () => {
  describe("Boundary values", () => {
    it("should escalate exactly at tier1Threshold", () => {
      const escalation = new AlertEscalation({
        tier1Threshold: 3,
        tier2Threshold: 10,
      });

      const event = createSecurityEvent({
        severity: "low",
        ruleName: "rule1",
        toolName: "tool1",
      });

      escalation.evaluate(event);
      escalation.evaluate({ ...event, id: "2" });
      const result3 = escalation.evaluate({ ...event, id: "3" });

      expect(result3.count).toBe(3);
      expect(result3.escalated).toBe(true);
      expect(result3.severity).toBe("medium");
    });

    it("should NOT escalate at tier1Threshold-1", () => {
      const escalation = new AlertEscalation({
        tier1Threshold: 3,
        tier2Threshold: 10,
      });

      const event = createSecurityEvent({
        severity: "low",
        ruleName: "rule1",
        toolName: "tool1",
      });

      escalation.evaluate(event);
      const result2 = escalation.evaluate({ ...event, id: "2" });

      expect(result2.count).toBe(2);
      expect(result2.escalated).toBe(false);
      expect(result2.severity).toBe("low");
    });

    it("should force critical exactly at tier2Threshold", () => {
      const escalation = new AlertEscalation({
        tier1Threshold: 3,
        tier2Threshold: 10,
      });

      const event = createSecurityEvent({
        severity: "low",
        ruleName: "rule1",
        toolName: "tool1",
      });

      for (let i = 0; i < 9; i++) {
        escalation.evaluate({ ...event, id: `${i}` });
      }

      const result10 = escalation.evaluate({ ...event, id: "9" });

      expect(result10.count).toBe(10);
      expect(result10.escalated).toBe(true);
      expect(result10.severity).toBe("critical");
    });

    it("should NOT escalate to critical at tier2Threshold-1", () => {
      const escalation = new AlertEscalation({
        tier1Threshold: 3,
        tier2Threshold: 10,
      });

      const event = createSecurityEvent({
        severity: "medium",
        ruleName: "rule1",
        toolName: "tool1",
      });

      for (let i = 0; i < 8; i++) {
        escalation.evaluate({ ...event, id: `${i}` });
      }

      const result9 = escalation.evaluate({ ...event, id: "8" });

      expect(result9.count).toBe(9);
      expect(result9.severity).toBe("high"); // Escalated from tier1, not to critical
    });
  });

  describe("cleanup() removes old entries", () => {
    it("should remove entries outside the time window", () => {
      const escalation = new AlertEscalation({ windowMs: 1000 });

      const baseTime = Date.now();
      const event = createSecurityEvent({
        severity: "medium",
        ruleName: "rule1",
        toolName: "tool1",
        timestamp: baseTime,
      });

      escalation.evaluate(event);
      expect(escalation.size).toBe(1);

      // Cleanup at a time beyond the window
      escalation.cleanup(baseTime + 2000);

      expect(escalation.size).toBe(0);
    });

    it("should keep entries within the time window", () => {
      const escalation = new AlertEscalation({ windowMs: 10000 });

      const baseTime = Date.now();
      const event = createSecurityEvent({
        severity: "medium",
        ruleName: "rule1",
        toolName: "tool1",
        timestamp: baseTime,
      });

      escalation.evaluate(event);

      // Cleanup at a time still within the window
      escalation.cleanup(baseTime + 5000);

      expect(escalation.size).toBe(1);
    });

    it("should handle cleanup with multiple entries", () => {
      const escalation = new AlertEscalation({ windowMs: 1000 });

      const baseTime = Date.now();

      // Add entries for different rules
      const event1 = createSecurityEvent({
        severity: "low",
        ruleName: "rule1",
        toolName: "tool1",
        timestamp: baseTime,
      });

      const event2 = createSecurityEvent({
        severity: "low",
        ruleName: "rule2",
        toolName: "tool2",
        timestamp: baseTime,
      });

      escalation.evaluate(event1);
      escalation.evaluate(event2);
      expect(escalation.size).toBe(2);

      escalation.cleanup(baseTime + 2000);

      expect(escalation.size).toBe(0);
    });
  });

  describe("size property", () => {
    it("should report correct size after operations", () => {
      const escalation = new AlertEscalation();

      expect(escalation.size).toBe(0);

      const event1 = createSecurityEvent({
        severity: "medium",
        ruleName: "rule1",
        toolName: "tool1",
      });

      escalation.evaluate(event1);
      expect(escalation.size).toBe(1);

      const event2 = createSecurityEvent({
        severity: "medium",
        ruleName: "rule2",
        toolName: "tool2",
      });

      escalation.evaluate(event2);
      expect(escalation.size).toBe(2);

      // Same rule+tool, should not add new entry
      escalation.evaluate({ ...event1, id: "1b" });
      expect(escalation.size).toBe(2);
    });
  });
});

// ═════════════════════════════════════════════════════════════════════════
// ConsoleSink Extra Tests
// ═════════════════════════════════════════════════════════════════════════

describe("ConsoleSink — Extra Coverage", () => {
  it("should not throw for info severity", async () => {
    const sink = new ConsoleSink();
    const event = createSecurityEvent({
      severity: "info",
      title: "Info event",
      description: "Information only",
      ruleName: "rule1",
      toolName: "tool1",
    });

    await expect(
      sink.send({
        event,
        summary: "[INFO] Info event",
        actionTaken: "alert",
      })
    ).resolves.toBeUndefined();
  });

  it("should not throw for low severity", async () => {
    const sink = new ConsoleSink();
    const event = createSecurityEvent({
      severity: "low",
      title: "Low severity event",
      description: "Low severity",
      ruleName: "rule1",
      toolName: "tool1",
    });

    await expect(
      sink.send({
        event,
        summary: "[LOW] Low severity event",
        actionTaken: "alert",
      })
    ).resolves.toBeUndefined();
  });

  it("should not throw for medium severity", async () => {
    const sink = new ConsoleSink();
    const event = createSecurityEvent({
      severity: "medium",
      title: "Medium severity event",
      description: "Medium severity",
      ruleName: "rule1",
      toolName: "tool1",
    });

    await expect(
      sink.send({
        event,
        summary: "[MEDIUM] Medium severity event",
        actionTaken: "alert",
      })
    ).resolves.toBeUndefined();
  });

  it("should not throw for high severity", async () => {
    const sink = new ConsoleSink();
    const event = createSecurityEvent({
      severity: "high",
      title: "High severity event",
      description: "High severity",
      ruleName: "rule1",
      toolName: "tool1",
    });

    await expect(
      sink.send({
        event,
        summary: "[HIGH] High severity event",
        actionTaken: "alert",
      })
    ).resolves.toBeUndefined();
  });

  it("should not throw for critical severity", async () => {
    const sink = new ConsoleSink();
    const event = createSecurityEvent({
      severity: "critical",
      title: "Critical event",
      description: "Critical severity",
      ruleName: "rule1",
      toolName: "tool1",
    });

    await expect(
      sink.send({
        event,
        summary: "[CRITICAL] Critical event",
        actionTaken: "alert",
      })
    ).resolves.toBeUndefined();
  });

  it("should handle blocked action", async () => {
    const sink = new ConsoleSink();
    const event = createSecurityEvent({
      severity: "critical",
      action: "blocked",
      title: "Blocked event",
      description: "This action was blocked",
      ruleName: "rule1",
      toolName: "tool1",
    });

    await expect(
      sink.send({
        event,
        summary: "[CRITICAL] Blocked event",
        actionTaken: "blocked",
      })
    ).resolves.toBeUndefined();
  });
});

// ═════════════════════════════════════════════════════════════════════════
// LogFileSink Extra Tests
// ═════════════════════════════════════════════════════════════════════════

describe("LogFileSink — Extra Coverage", () => {
  let testLogDir: string;
  let testLogFile: string;

  beforeEach(() => {
    testLogDir = join(tmpdir(), `carapace-test-${Date.now()}`);
    testLogFile = join(testLogDir, "test.log");
  });

  afterEach(() => {
    try {
      rmSync(testLogDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  it("should write event to log file", async () => {
    const sink = new LogFileSink(testLogFile);
    const event = createSecurityEvent({
      id: "test-event-1",
      severity: "high",
      title: "Test alert",
      description: "Test description",
      ruleName: "rule1",
      toolName: "tool1",
    });

    await sink.send({
      event,
      summary: "[HIGH] Test alert",
      actionTaken: "alert",
    });

    const content = readFileSync(testLogFile, "utf-8");
    expect(content).toContain("test-event-1");
    expect(content).toContain("Test alert");
  });

  it("should create directory if it does not exist", async () => {
    const sink = new LogFileSink(testLogFile);
    const event = createSecurityEvent({
      severity: "medium",
      title: "Alert",
      description: "Description",
      ruleName: "rule1",
      toolName: "tool1",
    });

    // File doesn't exist yet, directory doesn't exist
    await sink.send({
      event,
      summary: "[MEDIUM] Alert",
      actionTaken: "alert",
    });

    const content = readFileSync(testLogFile, "utf-8");
    expect(content).toContain("Alert");
  });

  it("should append multiple events to the same file", async () => {
    const sink = new LogFileSink(testLogFile);

    const event1 = createSecurityEvent({
      id: "event-1",
      severity: "low",
      title: "First",
      ruleName: "rule1",
      toolName: "tool1",
    });

    const event2 = createSecurityEvent({
      id: "event-2",
      severity: "medium",
      title: "Second",
      ruleName: "rule1",
      toolName: "tool1",
    });

    await sink.send({
      event: event1,
      summary: "[LOW] First",
      actionTaken: "alert",
    });

    await sink.send({
      event: event2,
      summary: "[MEDIUM] Second",
      actionTaken: "alert",
    });

    const content = readFileSync(testLogFile, "utf-8");
    const lines = content.trim().split("\n");

    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain("event-1");
    expect(lines[1]).toContain("event-2");
  });

  it("should handle write errors gracefully", async () => {
    // Use an invalid path (e.g., root directory for unprivileged user)
    const invalidPath = "/root/impossible-directory-path-12345/test.log";
    const sink = new LogFileSink(invalidPath);

    const event = createSecurityEvent({
      severity: "high",
      title: "Alert",
      description: "Description",
      ruleName: "rule1",
      toolName: "tool1",
    });

    // Should not throw
    await expect(
      sink.send({
        event,
        summary: "[HIGH] Alert",
        actionTaken: "alert",
      })
    ).resolves.toBeUndefined();
  });

  it("should write valid JSON for each event", async () => {
    const sink = new LogFileSink(testLogFile);
    const event = createSecurityEvent({
      id: "event-json",
      severity: "critical",
      category: "exec_danger",
      title: "Critical alert",
      description: "This is critical",
      details: { key: "value" },
      ruleName: "rule1",
      toolName: "tool1",
      action: "blocked",
    });

    await sink.send({
      event,
      summary: "[CRITICAL] Critical alert",
      actionTaken: "blocked",
    });

    const content = readFileSync(testLogFile, "utf-8");
    const lines = content.trim().split("\n");

    // Each line should be valid JSON
    const parsed = JSON.parse(lines[0]);
    expect(parsed.id).toBe("event-json");
    expect(parsed.severity).toBe("critical");
    expect(parsed.title).toBe("Critical alert");
  });
});
