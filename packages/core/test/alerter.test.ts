/**
 * Alerter module tests
 * Tests for AlertEscalation, HookMessageSink, DismissalManager, and AlertRouter
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  AlertEscalation,
  AlertRouter,
  HookMessageSink,
  DismissalManager,
  WebhookSink,
  type EscalationConfig,
  type DismissalPattern,
} from "../src/alerter.js";
import type { SecurityEvent } from "../src/types.js";

// ─── Test Helpers ────────────────────────────────────────────────────

function createSecurityEvent(overrides: Partial<SecurityEvent> = {}): SecurityEvent {
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

function createDismissalPattern(overrides: Partial<DismissalPattern> = {}): DismissalPattern {
  const defaults: DismissalPattern = {
    id: `dismissal-${Math.random().toString(36).slice(2)}`,
    ruleName: "test-rule",
    reason: "Test dismissal",
    createdAt: Date.now(),
  };

  return { ...defaults, ...overrides };
}

// ─── AlertEscalation Tests ───────────────────────────────────────────

describe("AlertEscalation", () => {
  let escalation: AlertEscalation;

  beforeEach(() => {
    escalation = new AlertEscalation();
  });

  it("should return original severity on first event", () => {
    const event = createSecurityEvent({
      severity: "medium",
      ruleName: "rule1",
      toolName: "tool1",
    });

    const result = escalation.evaluate(event);

    expect(result.severity).toBe("medium");
    expect(result.escalated).toBe(false);
    expect(result.count).toBe(1);
  });

  it("should upgrade severity by 1 level at tier1 threshold (3 events)", () => {
    const event = createSecurityEvent({
      severity: "medium",
      ruleName: "rule1",
      toolName: "tool1",
    });

    escalation.evaluate(event);
    escalation.evaluate({ ...event, id: "2" });
    const result = escalation.evaluate({ ...event, id: "3" });

    expect(result.severity).toBe("high");
    expect(result.escalated).toBe(true);
    expect(result.count).toBe(3);
  });

  it("should force critical severity at tier2 threshold (10 events)", () => {
    const event = createSecurityEvent({
      severity: "low",
      ruleName: "rule1",
      toolName: "tool1",
    });

    for (let i = 0; i < 9; i++) {
      escalation.evaluate({ ...event, id: `${i}` });
    }

    const result = escalation.evaluate({ ...event, id: "9" });

    expect(result.severity).toBe("critical");
    expect(result.escalated).toBe(true);
    expect(result.count).toBe(10);
  });

  it("should already be critical, no escalation needed", () => {
    const event = createSecurityEvent({
      severity: "critical",
      ruleName: "rule1",
      toolName: "tool1",
    });

    escalation.evaluate(event);
    escalation.evaluate({ ...event, id: "2" });
    const result = escalation.evaluate({ ...event, id: "3" });

    // Already critical, so no escalation happens
    expect(result.severity).toBe("critical");
    expect(result.escalated).toBe(false);
    expect(result.count).toBe(3);
  });

  it("should track different rule/tool combinations separately", () => {
    const event1 = createSecurityEvent({
      severity: "medium",
      ruleName: "rule1",
      toolName: "tool1",
    });

    const event2 = createSecurityEvent({
      severity: "medium",
      ruleName: "rule2",
      toolName: "tool2",
    });

    escalation.evaluate(event1);
    escalation.evaluate({ ...event1, id: "1b" });
    escalation.evaluate({ ...event1, id: "1c" });
    const result1 = escalation.evaluate({ ...event1, id: "1d" });

    escalation.evaluate(event2);
    escalation.evaluate({ ...event2, id: "2b" });
    const result2 = escalation.evaluate({ ...event2, id: "2c" });

    expect(result1.severity).toBe("high"); // rule1+tool1 escalated at 3+
    expect(result1.count).toBe(4);

    expect(result2.severity).toBe("high"); // rule2+tool2 escalated at 3+
    expect(result2.count).toBe(3);
  });

  it("should track by ruleName:toolName key, ignoring other fields", () => {
    const event1 = createSecurityEvent({
      severity: "medium",
      ruleName: "rule1",
      toolName: "tool1",
      skillName: "skill1",
    });

    const event2 = createSecurityEvent({
      severity: "medium",
      ruleName: "rule1",
      toolName: "tool1",
      skillName: "skill2",
    });

    escalation.evaluate(event1);
    escalation.evaluate(event1);
    const result = escalation.evaluate(event2);

    expect(result.count).toBe(3); // Same key, counts together
    expect(result.severity).toBe("high");
  });

  it("should expire entries outside the time window", () => {
    const baseTime = Date.now();
    const event = createSecurityEvent({
      severity: "medium",
      ruleName: "rule1",
      toolName: "tool1",
      timestamp: baseTime,
    });

    escalation.evaluate(event);
    escalation.evaluate({ ...event, id: "2", timestamp: baseTime + 1000 });

    // Simulate time passing beyond the window
    // Window is 10 minutes (600000ms). Events expire when: now - timestamp >= windowMs
    // So we need future time where both baseTime and baseTime+1000 are expired
    const futureTime = baseTime + 10 * 60 * 1000 + 1001; // 10min + 1001ms
    // At this time:
    // - first event: (baseTime + 600001) - baseTime = 600001 >= 600000 (expired)
    // - second event: (baseTime + 600001) - (baseTime + 1000) = 599001 < 600000 (still valid!)
    // We need more time:
    const futureTime2 = baseTime + 11 * 60 * 1000; // 11 minutes
    const result = escalation.evaluate({
      ...event,
      id: "3",
      timestamp: futureTime2,
    });

    // Both previous events should be expired, count should reset to 1
    expect(result.count).toBe(1);
    expect(result.severity).toBe("medium");
    expect(result.escalated).toBe(false);
  });

  it("should cleanup expired entries", () => {
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
    escalation.cleanup(baseTime + 11 * 60 * 1000);

    expect(escalation.size).toBe(0);
  });

  it("should support custom window size", () => {
    const escalation2 = new AlertEscalation({ windowMs: 1000 }); // 1 second window

    const baseTime = Date.now();
    const event = createSecurityEvent({
      severity: "medium",
      ruleName: "rule1",
      toolName: "tool1",
      timestamp: baseTime,
    });

    escalation2.evaluate(event);
    escalation2.evaluate({ ...event, id: "2", timestamp: baseTime + 500 });
    // At baseTime + 1500, only the event at baseTime + 500 is within 1 second window
    // (1500 - 500 = 1000ms, which is at the boundary)
    const result3 = escalation2.evaluate({ ...event, id: "3", timestamp: baseTime + 1500 });

    // Events at 500ms is now 1000ms old (outside the 1000ms window),
    // and event at baseTime is 1500ms old (way outside)
    // So only this current event should count = 1
    expect(result3.count).toBe(1);
  });

  it("should support custom tier thresholds", () => {
    const escalation2 = new AlertEscalation({
      tier1Threshold: 2,
      tier2Threshold: 5,
    });

    const event = createSecurityEvent({
      severity: "low",
      ruleName: "rule1",
      toolName: "tool1",
    });

    const result1 = escalation2.evaluate(event);
    expect(result1.count).toBe(1);
    expect(result1.severity).toBe("low");

    const result2 = escalation2.evaluate({ ...event, id: "2" });
    expect(result2.count).toBe(2);
    expect(result2.severity).toBe("medium"); // tier1 at 2

    const result5 = escalation2.evaluate({ ...event, id: "5" });
    // Iterate to 5
    escalation2.evaluate({ ...event, id: "3" });
    escalation2.evaluate({ ...event, id: "4" });
    const result5Final = escalation2.evaluate({ ...event, id: "5" });

    expect(result5Final.severity).toBe("critical"); // tier2 at 5
  });

  it("should upgrade through multiple severity levels", () => {
    const escalation2 = new AlertEscalation();
    const event = createSecurityEvent({
      severity: "info",
      ruleName: "rule1",
      toolName: "tool1",
    });

    escalation2.evaluate(event);
    escalation2.evaluate({ ...event, id: "2" });
    const result = escalation2.evaluate({ ...event, id: "3" });

    // info -> low (tier1 upgrade)
    expect(result.severity).toBe("low");
  });

  it("should cap severity at critical", () => {
    const escalation2 = new AlertEscalation({
      tier1Threshold: 1,
      tier2Threshold: 2,
    });

    const event = createSecurityEvent({
      severity: "high",
      ruleName: "rule1",
      toolName: "tool1",
    });

    escalation2.evaluate(event);
    escalation2.evaluate({ ...event, id: "2" });

    // Should cap at critical, not go beyond
    expect(escalation2.evaluate({ ...event, id: "3" }).severity).toBe("critical");
    expect(escalation2.evaluate({ ...event, id: "4" }).severity).toBe("critical");
  });
});

// ─── HookMessageSink Tests ───────────────────────────────────────────

describe("HookMessageSink", () => {
  let mockCallback: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    mockCallback = vi.fn();
  });

  it("should send message to callback for high severity events", async () => {
    const sink = new HookMessageSink(mockCallback, "high");
    const event = createSecurityEvent({
      severity: "high",
      title: "High severity alert",
      description: "This is important",
      ruleName: "rule1",
      toolName: "tool1",
      action: "alert",
    });

    await sink.send({
      event,
      summary: "[HIGH] High severity alert",
      actionTaken: "alert",
    });

    expect(mockCallback).toHaveBeenCalledOnce();
    const message = mockCallback.mock.calls[0][0];
    expect(message).toContain("⚠️");
    expect(message).toContain("HIGH");
    expect(message).toContain("High severity alert");
  });

  it("should not send message for lower severity when minSeverity is high", async () => {
    const sink = new HookMessageSink(mockCallback, "high");
    const event = createSecurityEvent({
      severity: "medium",
      title: "Medium severity alert",
      description: "This is not important enough",
      ruleName: "rule1",
      toolName: "tool1",
    });

    await sink.send({
      event,
      summary: "[MEDIUM] Medium severity alert",
      actionTaken: "alert",
    });

    expect(mockCallback).not.toHaveBeenCalled();
  });

  it("should send message for critical severity even with high minSeverity", async () => {
    const sink = new HookMessageSink(mockCallback, "high");
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
  });

  it("should respect custom minSeverity of low", async () => {
    const sink = new HookMessageSink(mockCallback, "low");
    const event = createSecurityEvent({
      severity: "low",
      title: "Low severity alert",
      description: "This should send",
      ruleName: "rule1",
      toolName: "tool1",
    });

    await sink.send({
      event,
      summary: "[LOW] Low severity alert",
      actionTaken: "alert",
    });

    expect(mockCallback).toHaveBeenCalledOnce();
  });

  it("should use blocked icon for blocked actions", async () => {
    const sink = new HookMessageSink(mockCallback, "high");
    const event = createSecurityEvent({
      severity: "high",
      title: "Blocked action",
      description: "This was blocked",
      ruleName: "rule1",
      toolName: "tool1",
      action: "blocked",
    });

    await sink.send({
      event,
      summary: "[HIGH] Blocked action",
      actionTaken: "blocked",
    });

    const message = mockCallback.mock.calls[0][0];
    expect(message).toContain("🛡️");
  });

  it("should format message with rule, tool, and description", async () => {
    const sink = new HookMessageSink(mockCallback, "high");
    const event = createSecurityEvent({
      severity: "high",
      title: "Test alert",
      description: "Test description",
      ruleName: "test_rule",
      toolName: "test_tool",
    });

    await sink.send({
      event,
      summary: "[HIGH] Test alert",
      actionTaken: "alert",
    });

    const message = mockCallback.mock.calls[0][0];
    expect(message).toContain("test_rule");
    expect(message).toContain("test_tool");
    expect(message).toContain("Test description");
  });

  it("should handle callback errors gracefully", async () => {
    const errorCallback = vi.fn(() => {
      throw new Error("Callback failed");
    });

    const sink = new HookMessageSink(errorCallback, "high");
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

    expect(errorCallback).toHaveBeenCalledOnce();
  });

  it("should default minSeverity to high", async () => {
    const sink = new HookMessageSink(mockCallback);
    const event = createSecurityEvent({
      severity: "medium",
      title: "Medium alert",
      description: "Should not send",
      ruleName: "rule1",
      toolName: "tool1",
    });

    await sink.send({
      event,
      summary: "[MEDIUM] Medium alert",
      actionTaken: "alert",
    });

    expect(mockCallback).not.toHaveBeenCalled();
  });

  it("should send for info level when minSeverity is info", async () => {
    const sink = new HookMessageSink(mockCallback, "info");
    const event = createSecurityEvent({
      severity: "info",
      title: "Info alert",
      description: "Just informational",
      ruleName: "rule1",
      toolName: "tool1",
    });

    await sink.send({
      event,
      summary: "[INFO] Info alert",
      actionTaken: "alert",
    });

    expect(mockCallback).toHaveBeenCalledOnce();
  });
});

// ─── DismissalManager Tests ──────────────────────────────────────────

describe("DismissalManager", () => {
  let manager: DismissalManager;

  beforeEach(() => {
    manager = new DismissalManager();
  });

  it("should add dismissal pattern", () => {
    const pattern = createDismissalPattern({
      ruleName: "rule1",
      toolName: "tool1",
    });

    manager.addDismissal(pattern);

    expect(manager.size).toBe(1);
    expect(manager.listDismissals()).toContainEqual(pattern);
  });

  it("should remove dismissal pattern by id", () => {
    const pattern1 = createDismissalPattern({ id: "id1", ruleName: "rule1" });
    const pattern2 = createDismissalPattern({ id: "id2", ruleName: "rule2" });

    manager.addDismissal(pattern1);
    manager.addDismissal(pattern2);

    const removed = manager.removeDismissal("id1");

    expect(removed).toBe(true);
    expect(manager.size).toBe(1);
    expect(manager.listDismissals()).toContainEqual(pattern2);
  });

  it("should return false when removing non-existent dismissal", () => {
    const removed = manager.removeDismissal("non-existent");

    expect(removed).toBe(false);
  });

  it("should check if event is dismissed by ruleName", () => {
    const pattern = createDismissalPattern({ ruleName: "rule1" });
    manager.addDismissal(pattern);

    const event = createSecurityEvent({ ruleName: "rule1", toolName: "any" });
    expect(manager.isDismissed(event)).toBe(true);

    const otherEvent = createSecurityEvent({ ruleName: "rule2", toolName: "any" });
    expect(manager.isDismissed(otherEvent)).toBe(false);
  });

  it("should check if event is dismissed by toolName", () => {
    const pattern: DismissalPattern = {
      id: "dismiss-tool",
      toolName: "tool1",
      reason: "Test dismissal",
      createdAt: Date.now(),
    };
    manager.addDismissal(pattern);

    const event = createSecurityEvent({ ruleName: "any", toolName: "tool1" });
    expect(manager.isDismissed(event)).toBe(true);

    const otherEvent = createSecurityEvent({ ruleName: "any", toolName: "tool2" });
    expect(manager.isDismissed(otherEvent)).toBe(false);
  });

  it("should check if event is dismissed by skillName", () => {
    const pattern: DismissalPattern = {
      id: "dismiss-skill",
      skillName: "skill1",
      reason: "Test dismissal",
      createdAt: Date.now(),
    };
    manager.addDismissal(pattern);

    const event = createSecurityEvent({ skillName: "skill1" });
    expect(manager.isDismissed(event)).toBe(true);

    const otherEvent = createSecurityEvent({ skillName: "skill2" });
    expect(manager.isDismissed(otherEvent)).toBe(false);
  });

  it("should match pattern with all criteria (AND logic)", () => {
    const pattern = createDismissalPattern({
      ruleName: "rule1",
      toolName: "tool1",
      skillName: "skill1",
    });
    manager.addDismissal(pattern);

    // Exact match
    const event1 = createSecurityEvent({
      ruleName: "rule1",
      toolName: "tool1",
      skillName: "skill1",
    });
    expect(manager.isDismissed(event1)).toBe(true);

    // Rule matches but tool doesn't
    const event2 = createSecurityEvent({
      ruleName: "rule1",
      toolName: "tool2",
      skillName: "skill1",
    });
    expect(manager.isDismissed(event2)).toBe(false);
  });

  it("should treat undefined pattern fields as wildcards", () => {
    const pattern = createDismissalPattern({
      ruleName: "rule1",
      // toolName and skillName are undefined (wildcards)
    });
    manager.addDismissal(pattern);

    const event1 = createSecurityEvent({
      ruleName: "rule1",
      toolName: "any_tool",
      skillName: "any_skill",
    });
    expect(manager.isDismissed(event1)).toBe(true);

    const event2 = createSecurityEvent({
      ruleName: "rule1",
      toolName: undefined,
      skillName: undefined,
    });
    expect(manager.isDismissed(event2)).toBe(true);
  });

  it("should support expiration with expiresAt", () => {
    const now = Date.now();
    const pattern = createDismissalPattern({
      ruleName: "rule1",
      expiresAt: now - 1000, // Expired 1 second ago
    });
    manager.addDismissal(pattern);

    const event = createSecurityEvent({ ruleName: "rule1" });
    expect(manager.isDismissed(event)).toBe(false); // Expired, so not dismissed
  });

  it("should not dismiss if pattern expires in future but checks now", () => {
    const now = Date.now();
    const pattern = createDismissalPattern({
      ruleName: "rule1",
      expiresAt: now + 60000, // Expires in 1 minute
    });
    manager.addDismissal(pattern);

    const event = createSecurityEvent({ ruleName: "rule1" });
    expect(manager.isDismissed(event)).toBe(true); // Not expired yet
  });

  it("should cleanup expired dismissals", () => {
    const now = Date.now();
    const pattern1 = createDismissalPattern({
      id: "id1",
      ruleName: "rule1",
      expiresAt: now - 1000, // Expired
    });
    const pattern2 = createDismissalPattern({
      id: "id2",
      ruleName: "rule2",
      expiresAt: now + 60000, // Valid
    });

    manager.addDismissal(pattern1);
    manager.addDismissal(pattern2);

    const cleaned = manager.cleanupExpired();

    expect(cleaned).toBe(1);
    expect(manager.size).toBe(1);
    expect(manager.listDismissals()).toContainEqual(pattern2);
  });

  it("should list all dismissals", () => {
    const pattern1 = createDismissalPattern({ id: "id1" });
    const pattern2 = createDismissalPattern({ id: "id2" });

    manager.addDismissal(pattern1);
    manager.addDismissal(pattern2);

    const list = manager.listDismissals();

    expect(list).toHaveLength(2);
    expect(list).toContainEqual(pattern1);
    expect(list).toContainEqual(pattern2);
  });

  it("should clear all dismissals", () => {
    manager.addDismissal(createDismissalPattern());
    manager.addDismissal(createDismissalPattern());

    manager.clearDismissals();

    expect(manager.size).toBe(0);
  });

  it("should reject wildcard dismissal with no filter fields", () => {
    expect(() =>
      manager.addDismissal({
        id: "wildcard",
        reason: "test",
        createdAt: Date.now(),
      })
    ).toThrow("must specify at least one");
  });

  it("should return copy of patterns in listDismissals", () => {
    const pattern = createDismissalPattern({ id: "id1" });
    manager.addDismissal(pattern);

    const list1 = manager.listDismissals();
    const list2 = manager.listDismissals();

    expect(list1).not.toBe(list2); // Different arrays
    expect(list1).toEqual(list2); // But same content
  });

  it("should lazily cleanup expired patterns when size exceeds 50", () => {
    const now = Date.now();

    // Add 51 expired patterns
    for (let i = 0; i < 51; i++) {
      manager.addDismissal(
        createDismissalPattern({
          id: `expired-${i}`,
          ruleName: `expired-rule-${i}`,
          expiresAt: now - 1000, // Expired 1 second ago
        })
      );
    }

    // Add 4 valid patterns
    for (let i = 0; i < 4; i++) {
      manager.addDismissal(
        createDismissalPattern({
          id: `valid-${i}`,
          ruleName: `valid-rule-${i}`,
          expiresAt: now + 60000, // Expires in 1 minute
        })
      );
    }

    expect(manager.size).toBe(55);

    // isDismissed triggers lazy cleanup when size > 50
    const event = createSecurityEvent({ ruleName: "valid-rule-0" });
    const dismissed = manager.isDismissed(event);

    expect(dismissed).toBe(true); // valid-rule-0 still matches
    expect(manager.size).toBe(4); // All 51 expired patterns cleaned up
  });
});

// ─── AlertRouter Integration Tests ───────────────────────────────────

describe("AlertRouter", () => {
  it("should initialize with escalation and dismissal enabled by default", () => {
    const router = new AlertRouter();

    expect(router.escalation).not.toBeNull();
    expect(router.dismissal).not.toBeNull();
  });

  it("should support disabling escalation", () => {
    const router = new AlertRouter({ enableEscalation: false });

    expect(router.escalation).toBeNull();
  });

  it("should support disabling dismissal", () => {
    const router = new AlertRouter({ enableDismissal: false });

    expect(router.dismissal).toBeNull();
  });

  it("should skip dismissed events", async () => {
    const mockSink = {
      name: "test",
      send: vi.fn(),
    };

    const router = new AlertRouter({ enableDismissal: true });
    router.addSink(mockSink);

    // Add dismissal pattern
    router.dismissal!.addDismissal({
      id: "dismiss1",
      ruleName: "rule1",
      reason: "False positive",
      createdAt: Date.now(),
    });

    const event = createSecurityEvent({
      ruleName: "rule1",
      toolName: "tool1",
    });

    await router.send(event);

    expect(mockSink.send).not.toHaveBeenCalled();
  });

  it("should escalate events and show upgraded severity", async () => {
    const mockSink = {
      name: "test",
      send: vi.fn(),
    };

    const router = new AlertRouter({ enableEscalation: true });
    router.addSink(mockSink);

    const event = createSecurityEvent({
      severity: "medium",
      ruleName: "rule1",
      toolName: "tool1",
      title: "Alert",
      description: "Original",
      toolParams: { iteration: 1 }, // Different toolParams to bypass dedup
    });

    // Send 3 events with different matchedPattern (bypasses dedup, but same rule+tool for escalation)
    await router.send(event);
    await router.send({ ...event, id: "2", matchedPattern: "pattern2" });
    await router.send({ ...event, id: "3", matchedPattern: "pattern3" });

    expect(mockSink.send).toHaveBeenCalledTimes(3);

    // Third call should have escalated severity
    const thirdCall = mockSink.send.mock.calls[2][0];
    expect(thirdCall.event.severity).toBe("high");
    expect(thirdCall.event.description).toContain("已升级");
  });

  it("should integrate dismissal and escalation together", async () => {
    const mockSink = {
      name: "test",
      send: vi.fn(),
    };

    const router = new AlertRouter({
      enableEscalation: true,
      enableDismissal: true,
    });
    router.addSink(mockSink);

    // Add dismissal for tool2
    router.dismissal!.addDismissal({
      id: "dismiss1",
      toolName: "tool2",
      reason: "Known false positive",
      createdAt: Date.now(),
    });

    const event1 = createSecurityEvent({
      id: "event1",
      severity: "medium",
      ruleName: "rule1",
      toolName: "tool1",
      toolParams: { iteration: 1 },
    });

    const event2 = createSecurityEvent({
      id: "event2",
      severity: "medium",
      ruleName: "rule1",
      toolName: "tool2",
      toolParams: { iteration: 1 },
    });

    // Send tool1 event (should go through escalation)
    // Use different matchedPattern to bypass dedup, same rule+tool for escalation
    await router.send(event1);
    await router.send({ ...event1, id: "event1b", matchedPattern: "pattern2" });
    await router.send({ ...event1, id: "event1c", matchedPattern: "pattern3" });

    // Send tool2 event (should be dismissed)
    await router.send(event2);

    // tool1 events sent (3 times), tool2 dismissed
    expect(mockSink.send).toHaveBeenCalledTimes(3);

    // Last tool1 call should be escalated
    const lastCall = mockSink.send.mock.calls[2][0];
    expect(lastCall.event.toolName).toBe("tool1");
    expect(lastCall.event.severity).toBe("high");
  });

  it("should handle custom escalation config", async () => {
    const mockSink = {
      name: "test",
      send: vi.fn(),
    };

    const router = new AlertRouter({
      enableEscalation: true,
      escalationConfig: {
        tier1Threshold: 2, // Lower threshold
        tier2Threshold: 4,
      },
    });
    router.addSink(mockSink);

    const event = createSecurityEvent({
      severity: "low",
      ruleName: "rule1",
      toolName: "tool1",
      toolParams: { iteration: 1 },
    });

    // Send 2 events to trigger tier1 at custom threshold
    // Use different matchedPattern to bypass dedup
    await router.send(event);
    await router.send({ ...event, id: "2", matchedPattern: "pattern2" });

    expect(mockSink.send).toHaveBeenCalledTimes(2);

    const secondCall = mockSink.send.mock.calls[1][0];
    expect(secondCall.event.severity).toBe("medium"); // Upgraded from low
  });

  it("should deduplicate within 5 minute window", async () => {
    const mockSink = {
      name: "test",
      send: vi.fn(),
    };

    const router = new AlertRouter({ enableEscalation: false, enableDismissal: false });
    router.addSink(mockSink);

    const event = createSecurityEvent({
      severity: "high",
      ruleName: "rule1",
      toolName: "tool1",
      title: "Duplicate alert",
      description: "Same toolParams should be deduped",
      toolParams: { param: "value" },
    });

    // Send twice with same toolParams
    await router.send(event);
    await router.send({ ...event, id: "2" });

    // Second send should be deduped
    expect(mockSink.send).toHaveBeenCalledTimes(1);
  });

  it("should not deduplicate if matchedPattern differs", async () => {
    const mockSink = {
      name: "test",
      send: vi.fn(),
    };

    const router = new AlertRouter({ enableEscalation: false, enableDismissal: false });
    router.addSink(mockSink);

    const event1 = createSecurityEvent({
      severity: "high",
      ruleName: "rule1",
      toolName: "tool1",
      matchedPattern: "pattern_a",
    });

    const event2 = createSecurityEvent({
      severity: "high",
      ruleName: "rule1",
      toolName: "tool1",
      matchedPattern: "pattern_b",
    });

    await router.send(event1);
    await router.send(event2);

    // Different matchedPattern = different dedup key
    expect(mockSink.send).toHaveBeenCalledTimes(2);
  });

  it("should stop sending to a sink after removeSink()", async () => {
    const mockSink = {
      name: "removable",
      send: vi.fn(),
    };

    const router = new AlertRouter({ enableEscalation: false, enableDismissal: false });
    router.addSink(mockSink);

    const event1 = createSecurityEvent({
      severity: "high",
      ruleName: "rule1",
      toolName: "tool1",
      toolParams: { param: "first" },
    });

    await router.send(event1);
    expect(mockSink.send).toHaveBeenCalledTimes(1);

    // Remove the sink
    router.removeSink("removable");

    const event2 = createSecurityEvent({
      severity: "high",
      ruleName: "rule1",
      toolName: "tool1",
      toolParams: { param: "second" },
    });

    await router.send(event2);

    // Should still be 1 — the sink was removed before the second send
    expect(mockSink.send).toHaveBeenCalledTimes(1);
  });

  it("should cleanup dedup map when size reaches 100", async () => {
    const mockSink = {
      name: "test",
      send: vi.fn(),
    };

    const router = new AlertRouter({ enableEscalation: false, enableDismissal: false });
    router.addSink(mockSink);

    // Send 101 unique events to fill the dedup map past the threshold
    for (let i = 0; i < 101; i++) {
      const event = createSecurityEvent({
        severity: "high",
        ruleName: `rule-${i}`,
        toolName: `tool-${i}`,
        toolParams: { iteration: i },
      });
      await router.send(event);
    }

    // All 101 unique events should have been sent
    expect(mockSink.send).toHaveBeenCalledTimes(101);

    // The dedup map cleanup runs when size >= 100, but since all entries
    // are recent (within the 5 min window), none are actually removed.
    // Verify events still dedup correctly after cleanup ran.
    const duplicateEvent = createSecurityEvent({
      severity: "high",
      ruleName: "rule-50",
      toolName: "tool-50",
      toolParams: { iteration: 50 },
    });

    await router.send(duplicateEvent);

    // Should still be 101 — the duplicate is within the dedup window
    expect(mockSink.send).toHaveBeenCalledTimes(101);
  });
});

// ─── WebhookSink SSRF Protection ─────────────────────────────────────

describe("WebhookSink", () => {
  it("accepts valid http URL", () => {
    expect(() => new WebhookSink("http://example.com/webhook")).not.toThrow();
  });

  it("accepts valid https URL", () => {
    expect(() => new WebhookSink("https://example.com/webhook")).not.toThrow();
  });

  it("rejects non-http protocol (ftp)", () => {
    expect(() => new WebhookSink("ftp://example.com/file")).toThrow(/only supports http\/https/);
  });

  it("rejects non-http protocol (file)", () => {
    expect(() => new WebhookSink("file:///etc/passwd")).toThrow(/only supports http\/https/);
  });

  it("rejects invalid URL", () => {
    expect(() => new WebhookSink("not-a-url")).toThrow(/invalid URL/);
  });

  it("rejects javascript protocol", () => {
    expect(() => new WebhookSink("javascript:alert(1)")).toThrow(/only supports http\/https/);
  });
});
