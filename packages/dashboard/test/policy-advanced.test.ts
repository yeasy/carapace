/**
 * policy-advanced.test.ts — Advanced policy management tests
 *
 * Comprehensive tests for complex policy scenarios:
 * - Policy inheritance chains (org → team → project)
 * - Conflict resolution (child overrides parent)
 * - Empty rules and invalid references
 * - Multiple policy layers with merging
 * - Enable/disable toggling
 */

import { describe, it, expect, beforeEach } from "vitest";
import {
  PolicyManager,
  POLICY_TEMPLATES,
  type PolicyDefinition,
  type ResolvedPolicy,
  type ImportResult,
} from "../src/policy.js";

// ─── Test Helpers ────────────────────────────────────────────

function createPolicy(
  name: string,
  overrides?: Partial<PolicyDefinition>
): PolicyDefinition {
  return {
    name,
    description: `Policy: ${name}`,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    config: {
      blockOnCritical: false,
      maxToolCallsPerMinute: 60,
    },
    ...overrides,
  };
}

// ═══════════════════════════════════════════════════════════
// Basic Policy Operations
// ═══════════════════════════════════════════════════════════

describe("PolicyManager basic operations", () => {
  let manager: PolicyManager;

  beforeEach(() => {
    manager = new PolicyManager();
  });

  it("adds policy successfully", () => {
    const policy = createPolicy("test-policy");
    manager.addPolicy(policy);

    expect(manager.size).toBe(1);
    expect(manager.getPolicy("test-policy")).toBeDefined();
  });

  it("retrieves policy by name", () => {
    const policy = createPolicy("my-policy");
    manager.addPolicy(policy);

    const retrieved = manager.getPolicy("my-policy");
    expect(retrieved?.name).toBe("my-policy");
    expect(retrieved?.description).toBe("Policy: my-policy");
  });

  it("returns undefined for non-existent policy", () => {
    expect(manager.getPolicy("non-existent")).toBeUndefined();
  });

  it("removes policy successfully", () => {
    const policy = createPolicy("to-remove");
    manager.addPolicy(policy);
    expect(manager.size).toBe(1);

    const removed = manager.removePolicy("to-remove");
    expect(removed).toBe(true);
    expect(manager.size).toBe(0);
  });

  it("returns false when removing non-existent policy", () => {
    const removed = manager.removePolicy("non-existent");
    expect(removed).toBe(false);
  });

  it("lists all policies", () => {
    manager.addPolicy(createPolicy("policy-1"));
    manager.addPolicy(createPolicy("policy-2"));
    manager.addPolicy(createPolicy("policy-3"));

    const all = manager.listPolicies();
    expect(all).toHaveLength(3);
    expect(all.map((p) => p.name)).toContain("policy-1");
    expect(all.map((p) => p.name)).toContain("policy-2");
    expect(all.map((p) => p.name)).toContain("policy-3");
  });
});

// ═══════════════════════════════════════════════════════════
// Policy Inheritance Chain (org → team → project)
// ═══════════════════════════════════════════════════════════

describe("Policy inheritance chains", () => {
  let manager: PolicyManager;

  beforeEach(() => {
    manager = new PolicyManager();
  });

  it("resolves single policy without inheritance", () => {
    const policy = createPolicy("standalone");
    manager.addPolicy(policy);

    const resolved = manager.resolvePolicy("standalone");
    expect(resolved.name).toBe("standalone");
    expect(resolved.config.blockOnCritical).toBe(false);
  });

  it("resolves parent -> child inheritance", () => {
    const parentPolicy = createPolicy("parent", {
      config: {
        blockOnCritical: true,
        maxToolCallsPerMinute: 30,
        debug: false,
      },
    });

    const childPolicy = createPolicy("child", {
      extends: "parent",
      config: {
        blockOnCritical: false, // Override parent
        maxToolCallsPerMinute: 60,
      },
    });

    manager.addPolicy(parentPolicy);
    manager.addPolicy(childPolicy);

    const resolved = manager.resolvePolicy("child");
    expect(resolved.name).toBe("child");
    expect(resolved.config.blockOnCritical).toBe(false); // Child override
    expect(resolved.config.maxToolCallsPerMinute).toBe(60); // Child override
    expect(resolved.config.debug).toBe(false); // Inherited from parent
  });

  it("resolves org -> team -> project inheritance chain", () => {
    // org-level policy
    const orgPolicy = createPolicy("org-base", {
      config: {
        blockOnCritical: false,
        maxToolCallsPerMinute: 100,
        debug: false,
        trustedSkills: ["org-safe-skill"],
      },
    });

    // team-level policy extends org
    const teamPolicy = createPolicy("team-prod", {
      extends: "org-base",
      config: {
        maxToolCallsPerMinute: 50, // More restrictive
        trustedSkills: ["team-safe-skill"],
      },
    });

    // project-level policy extends team
    const projectPolicy = createPolicy("project-critical", {
      extends: "team-prod",
      config: {
        blockOnCritical: true, // Stricter than org
        maxToolCallsPerMinute: 20, // Even more restrictive
      },
    });

    manager.addPolicy(orgPolicy);
    manager.addPolicy(teamPolicy);
    manager.addPolicy(projectPolicy);

    const resolved = manager.resolvePolicy("project-critical");

    expect(resolved.name).toBe("project-critical");
    expect(resolved.config.blockOnCritical).toBe(true); // From project
    expect(resolved.config.maxToolCallsPerMinute).toBe(20); // From project
    expect(resolved.config.debug).toBe(false); // From org
  });

  it("detects circular inheritance", () => {
    const policy1 = createPolicy("policy-1", { extends: "policy-2" });
    const policy2 = createPolicy("policy-2", { extends: "policy-1" });

    manager.addPolicy(policy1);
    manager.addPolicy(policy2);

    expect(() => manager.resolvePolicy("policy-1")).toThrow(/Circular/);
  });

  it("detects missing parent policy", () => {
    const policy = createPolicy("orphan", { extends: "non-existent-parent" });
    manager.addPolicy(policy);

    expect(() => manager.resolvePolicy("orphan")).toThrow(/not found/);
  });
});

// ═══════════════════════════════════════════════════════════
// Policy Conflict Resolution (child overrides parent)
// ═══════════════════════════════════════════════════════════

describe("Policy conflict resolution", () => {
  let manager: PolicyManager;

  beforeEach(() => {
    manager = new PolicyManager();
  });

  it("child config completely overrides parent config", () => {
    const parent = createPolicy("parent", {
      config: {
        blockOnCritical: false,
        maxToolCallsPerMinute: 100,
        enableBaseline: true,
        debug: true,
      },
    });

    const child = createPolicy("child", {
      extends: "parent",
      config: {
        blockOnCritical: true,
        maxToolCallsPerMinute: 50,
      },
    });

    manager.addPolicy(parent);
    manager.addPolicy(child);

    const resolved = manager.resolvePolicy("child");
    expect(resolved.config.blockOnCritical).toBe(true);
    expect(resolved.config.maxToolCallsPerMinute).toBe(50);
    expect(resolved.config.enableBaseline).toBe(true);
    expect(resolved.config.debug).toBe(true);
  });

  it("merges trustedSkills from parent and child", () => {
    const parent = createPolicy("parent", {
      config: {
        trustedSkills: ["skill-a", "skill-b"],
      },
    });

    const child = createPolicy("child", {
      extends: "parent",
      config: {
        trustedSkills: ["skill-c"],
      },
    });

    manager.addPolicy(parent);
    manager.addPolicy(child);

    const resolved = manager.resolvePolicy("child");
    expect(resolved.trustedSkills).toContain("skill-a");
    expect(resolved.trustedSkills).toContain("skill-b");
    expect(resolved.trustedSkills).toContain("skill-c");
  });

  it("merges overrides from multiple levels", () => {
    const org = createPolicy("org", {
      config: {},
      overrides: {
        forceBlock: ["rule-1"],
        disabledRules: ["rule-2"],
        additionalTrustedSkills: ["org-skill"],
      },
    });

    const team = createPolicy("team", {
      extends: "org",
      overrides: {
        forceBlock: ["rule-3"],
        additionalTrustedSkills: ["team-skill"],
      },
    });

    manager.addPolicy(org);
    manager.addPolicy(team);

    const resolved = manager.resolvePolicy("team");
    expect(resolved.forceBlock).toContain("rule-1");
    expect(resolved.forceBlock).toContain("rule-3");
    expect(resolved.disabledRules).toContain("rule-2");
    expect(resolved.trustedSkills).toContain("org-skill");
    expect(resolved.trustedSkills).toContain("team-skill");
  });

  it("mergeChain filters non-string entries from trustedSkills", () => {
    // Simulate a policy with non-string trustedSkills that bypassed import validation
    const policy = createPolicy("bad-trusted", {
      config: {
        trustedSkills: ["valid-skill", 123 as unknown as string, null as unknown as string],
      },
    });
    manager.addPolicy(policy);

    const resolved = manager.resolvePolicy("bad-trusted");
    expect(resolved.trustedSkills).toEqual(["valid-skill"]);
  });

  it("removes duplicates after merging", () => {
    const parent = createPolicy("parent", {
      config: {
        trustedSkills: ["skill-1", "skill-2"],
      },
      overrides: {
        forceBlock: ["rule-1", "rule-2"],
      },
    });

    const child = createPolicy("child", {
      extends: "parent",
      config: {
        trustedSkills: ["skill-1", "skill-3"], // skill-1 is duplicate
      },
      overrides: {
        forceBlock: ["rule-1", "rule-3"], // rule-1 is duplicate
      },
    });

    manager.addPolicy(parent);
    manager.addPolicy(child);

    const resolved = manager.resolvePolicy("child");
    const forceBlockCount = resolved.forceBlock.filter(
      (r) => r === "rule-1"
    ).length;
    const skillCount = resolved.trustedSkills.filter(
      (s) => s === "skill-1"
    ).length;

    expect(forceBlockCount).toBe(1);
    expect(skillCount).toBe(1);
  });
});

// ═══════════════════════════════════════════════════════════
// Empty Rules and Invalid References
// ═══════════════════════════════════════════════════════════

describe("Policy with empty rules and invalid references", () => {
  let manager: PolicyManager;

  beforeEach(() => {
    manager = new PolicyManager();
  });

  it("handles policy with empty YAML rules", () => {
    const policy = createPolicy("empty-rules", {
      yamlRules: "",
    });
    manager.addPolicy(policy);

    const resolved = manager.resolvePolicy("empty-rules");
    expect(resolved).toBeDefined();
    expect(resolved.yamlRules).toHaveLength(0);
  });

  it("handles policy with null YAML rules", () => {
    const policy = createPolicy("null-rules", {
      yamlRules: undefined,
    });
    manager.addPolicy(policy);

    const resolved = manager.resolvePolicy("null-rules");
    expect(resolved).toBeDefined();
  });

  it("handles policy with empty overrides", () => {
    const policy = createPolicy("no-overrides", {
      overrides: {},
    });
    manager.addPolicy(policy);

    const resolved = manager.resolvePolicy("no-overrides");
    expect(resolved.forceBlock).toHaveLength(0);
    expect(resolved.disabledRules).toHaveLength(0);
  });

  it("handles policy with empty force block list", () => {
    const policy = createPolicy("empty-force-block", {
      overrides: {
        forceBlock: [],
      },
    });
    manager.addPolicy(policy);

    const resolved = manager.resolvePolicy("empty-force-block");
    expect(resolved.forceBlock).toHaveLength(0);
  });

  it("accumulates YAML rules from inheritance chain", () => {
    const parent = createPolicy("parent", {
      yamlRules: "rules: parent",
    });

    const child = createPolicy("child", {
      extends: "parent",
      yamlRules: "rules: child",
    });

    const grandchild = createPolicy("grandchild", {
      extends: "child",
      yamlRules: "rules: grandchild",
    });

    manager.addPolicy(parent);
    manager.addPolicy(child);
    manager.addPolicy(grandchild);

    const resolved = manager.resolvePolicy("grandchild");
    expect(resolved.yamlRules).toHaveLength(3);
    expect(resolved.yamlRules[0]).toContain("parent");
    expect(resolved.yamlRules[1]).toContain("child");
    expect(resolved.yamlRules[2]).toContain("grandchild");
  });
});

// ═══════════════════════════════════════════════════════════
// Active Policy Management
// ═══════════════════════════════════════════════════════════

describe("Active policy management", () => {
  let manager: PolicyManager;

  beforeEach(() => {
    manager = new PolicyManager();
  });

  it("sets and retrieves active policy", () => {
    const policy = createPolicy("active");
    manager.addPolicy(policy);

    manager.setActivePolicy("active");
    expect(manager.getActivePolicyName()).toBe("active");
  });

  it("returns null when no active policy set", () => {
    expect(manager.getActivePolicyName()).toBeNull();
  });

  it("throws when setting non-existent policy as active", () => {
    expect(() => manager.setActivePolicy("non-existent")).toThrow();
  });

  it("resolveActivePolicy returns null when no policy set", () => {
    expect(manager.resolveActivePolicy()).toBeNull();
  });

  it("resolveActivePolicy returns resolved policy when set", () => {
    const policy = createPolicy("active", {
      config: { blockOnCritical: true },
    });
    manager.addPolicy(policy);
    manager.setActivePolicy("active");

    const resolved = manager.resolveActivePolicy();
    expect(resolved).toBeDefined();
    expect(resolved?.name).toBe("active");
    expect(resolved?.config.blockOnCritical).toBe(true);
  });

  it("clears active policy when removing it", () => {
    const policy = createPolicy("to-remove");
    manager.addPolicy(policy);
    manager.setActivePolicy("to-remove");
    manager.removePolicy("to-remove");

    expect(manager.getActivePolicyName()).toBeNull();
  });

  it("maintains active policy when removing other policies", () => {
    manager.addPolicy(createPolicy("policy-1"));
    manager.addPolicy(createPolicy("policy-2"));

    manager.setActivePolicy("policy-1");
    manager.removePolicy("policy-2");

    expect(manager.getActivePolicyName()).toBe("policy-1");
  });
});

// ═══════════════════════════════════════════════════════════
// Import/Export
// ═══════════════════════════════════════════════════════════

describe("Policy import/export", () => {
  let manager: PolicyManager;

  beforeEach(() => {
    manager = new PolicyManager();
  });

  it("exports empty policies", () => {
    const json = manager.exportPolicies();
    const data = JSON.parse(json);

    expect(data.policies).toEqual([]);
    expect(data.version).toBe("1.0");
    expect(data.exportedAt).toBeDefined();
  });

  it("exports all policies with correct structure", () => {
    manager.addPolicy(createPolicy("policy-1"));
    manager.addPolicy(createPolicy("policy-2"));

    const json = manager.exportPolicies();
    const data = JSON.parse(json);

    expect(data.policies).toHaveLength(2);
    expect(data.policies[0].name).toBe("policy-1");
    expect(data.policies[1].name).toBe("policy-2");
  });

  it("imports policies correctly and returns ImportResult", () => {
    const policy1 = createPolicy("import-1");
    const policy2 = createPolicy("import-2");

    const json = JSON.stringify({
      policies: [policy1, policy2],
    });

    const result = manager.importPolicies(json);

    expect(result.imported).toBe(2);
    expect(result.skipped).toBe(0);
    expect(manager.size).toBe(2);
    expect(manager.getPolicy("import-1")).toBeDefined();
    expect(manager.getPolicy("import-2")).toBeDefined();
  });

  it("does NOT auto-activate imported activePolicy", () => {
    const policy = createPolicy("imported");

    const json = JSON.stringify({
      policies: [policy],
      activePolicy: "imported",
    });

    const result = manager.importPolicies(json);

    // activePolicy is returned in the result but not auto-applied
    expect(result.activePolicy).toBe("imported");
    expect(manager.getActivePolicyName()).toBeNull();
  });

  it("round-trip export/import preserves policy data", () => {
    const original = createPolicy("original", {
      config: {
        blockOnCritical: true,
        maxToolCallsPerMinute: 42,
        trustedSkills: ["skill-1", "skill-2"],
      },
      overrides: {
        forceBlock: ["rule-x"],
      },
    });

    manager.addPolicy(original);
    manager.setActivePolicy("original");

    const exported = manager.exportPolicies();

    const manager2 = new PolicyManager();
    const result = manager2.importPolicies(exported);

    const restored = manager2.getPolicy("original");
    expect(restored?.config.blockOnCritical).toBe(true);
    expect(restored?.config.maxToolCallsPerMinute).toBe(42);
    expect(restored?.overrides?.forceBlock).toContain("rule-x");
    // activePolicy is reported but not auto-applied
    expect(result.activePolicy).toBe("original");
    expect(manager2.getActivePolicyName()).toBeNull();
    // caller can explicitly activate if desired
    manager2.setActivePolicy("original");
    expect(manager2.getActivePolicyName()).toBe("original");
  });

  it("importPolicies throws on invalid format (non-object)", () => {
    expect(() => manager.importPolicies('"just a string"')).toThrow("Invalid import format");
  });

  it("importPolicies throws on missing policies array", () => {
    expect(() => manager.importPolicies('{"foo": "bar"}')).toThrow("Invalid import format");
  });

  it("importPolicies skips entries without name", () => {
    const json = JSON.stringify({
      policies: [
        { name: "valid", description: "ok" },
        { description: "no name" },
      ],
    });
    const result = manager.importPolicies(json);
    expect(result.imported).toBe(1);
    expect(result.skipped).toBe(1);
  });

  it("importPolicies skips policy with non-boolean blockOnCritical", () => {
    const json = JSON.stringify({
      policies: [
        { name: "bad-block", config: { blockOnCritical: "yes" } },
        { name: "good", config: { blockOnCritical: true } },
      ],
    });
    const result = manager.importPolicies(json);
    expect(result.imported).toBe(1);
    expect(result.skipped).toBe(1);
    expect(manager.getPolicy("bad-block")).toBeUndefined();
    expect(manager.getPolicy("good")).toBeDefined();
  });

  it("importPolicies skips policy with non-array trustedSkills", () => {
    const json = JSON.stringify({
      policies: [
        { name: "bad-skills", config: { trustedSkills: "not-an-array" } },
      ],
    });
    const result = manager.importPolicies(json);
    expect(result.imported).toBe(0);
    expect(result.skipped).toBe(1);
  });

  it("importPolicies skips policy with non-string entries in trustedSkills", () => {
    const json = JSON.stringify({
      policies: [
        { name: "bad-skills2", config: { trustedSkills: ["ok", 123, null] } },
      ],
    });
    const result = manager.importPolicies(json);
    expect(result.imported).toBe(0);
    expect(result.skipped).toBe(1);
  });

  it("importPolicies skips policy with non-string entries in override arrays", () => {
    const json = JSON.stringify({
      policies: [
        { name: "bad-fb", config: {}, overrides: { forceBlock: [1, 2] } },
        { name: "bad-dr", config: {}, overrides: { disabledRules: [true] } },
        { name: "bad-ats", config: {}, overrides: { additionalTrustedSkills: [{}] } },
        { name: "good-override", config: {}, overrides: { forceBlock: ["rule-1"] } },
      ],
    });
    const result = manager.importPolicies(json);
    expect(result.imported).toBe(1);
    expect(result.skipped).toBe(3);
    expect(manager.getPolicy("good-override")).toBeDefined();
  });

  it("importPolicies accepts valid config with all optional fields", () => {
    const json = JSON.stringify({
      policies: [
        {
          name: "full-valid",
          config: {
            blockOnCritical: false,
            trustedSkills: ["s1", "s2"],
          },
          overrides: {
            forceBlock: ["r1"],
            disabledRules: ["r2"],
            additionalTrustedSkills: ["s3"],
          },
        },
      ],
    });
    const result = manager.importPolicies(json);
    expect(result.imported).toBe(1);
    expect(result.skipped).toBe(0);
  });

  it("importPolicies returns null activePolicy when not provided", () => {
    const json = JSON.stringify({ policies: [] });
    const result = manager.importPolicies(json);
    expect(result.activePolicy).toBeNull();
  });
});

// ═══════════════════════════════════════════════════════════
// Policy Templates
// ═══════════════════════════════════════════════════════════

describe("Policy templates", () => {
  it("permissive template is available", () => {
    expect(POLICY_TEMPLATES.permissive).toBeDefined();
    expect(POLICY_TEMPLATES.permissive.config.blockOnCritical).toBe(false);
  });

  it("standard template is available", () => {
    expect(POLICY_TEMPLATES.standard).toBeDefined();
    expect(POLICY_TEMPLATES.standard.config.blockOnCritical).toBe(true);
  });

  it("strict template is available", () => {
    expect(POLICY_TEMPLATES.strict).toBeDefined();
    expect(POLICY_TEMPLATES.strict.config.blockOnCritical).toBe(true);
    expect(POLICY_TEMPLATES.strict.config.maxToolCallsPerMinute).toBe(30);
  });

  it("can instantiate from templates", () => {
    const manager = new PolicyManager();

    const permissive = {
      ...POLICY_TEMPLATES.permissive,
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };

    manager.addPolicy(permissive);
    manager.setActivePolicy("permissive");

    const resolved = manager.resolveActivePolicy();
    expect(resolved?.config.blockOnCritical).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════
// Edge Cases
// ═══════════════════════════════════════════════════════════

describe("Policy edge cases", () => {
  let manager: PolicyManager;

  beforeEach(() => {
    manager = new PolicyManager();
  });

  it("rejects policy with very long name", () => {
    const longName = "x".repeat(1000);
    const policy = createPolicy(longName);
    expect(() => manager.addPolicy(policy)).toThrow("Invalid policy name");
  });

  it("rejects policy with special characters in name", () => {
    const specialName = "policy-with-$pecial_ch@rs!";
    const policy = createPolicy(specialName);
    expect(() => manager.addPolicy(policy)).toThrow("Invalid policy name");
  });

  it("accepts policy with valid name characters", () => {
    const validName = "my-policy_v2.0";
    const policy = createPolicy(validName);
    manager.addPolicy(policy);
    expect(manager.getPolicy(validName)).toBeDefined();
  });

  it("handles policy with NaN timestamps", () => {
    const policy = createPolicy("nan-time", {
      createdAt: NaN,
      updatedAt: NaN,
    });

    expect(() => manager.addPolicy(policy)).not.toThrow();
  });

  it("updates updatedAt on policy addition", () => {
    const policy = createPolicy("test", { updatedAt: 0 });
    manager.addPolicy(policy);

    const retrieved = manager.getPolicy("test");
    expect(retrieved?.updatedAt).toBeGreaterThan(0);
  });

  it("handles inheritance chains up to depth limit", () => {
    let current = "level-0";
    const policies = [createPolicy(current)];

    // Build chain of 9 levels (within max depth of 10)
    for (let i = 1; i < 10; i++) {
      const next = `level-${i}`;
      policies.push(
        createPolicy(next, { extends: current })
      );
      current = next;
    }

    policies.forEach((p) => manager.addPolicy(p));

    const resolved = manager.resolvePolicy("level-9");
    expect(resolved.name).toBe("level-9");
  });

  it("rejects inheritance chains exceeding depth limit", () => {
    let current = "deep-0";
    const policies = [createPolicy(current)];

    for (let i = 1; i <= 11; i++) {
      const next = `deep-${i}`;
      policies.push(
        createPolicy(next, { extends: current })
      );
      current = next;
    }

    policies.forEach((p) => manager.addPolicy(p));

    expect(() => manager.resolvePolicy("deep-11")).toThrow("too deep");
  });
});

// ═══════════════════════════════════════════════════════════
// Policy Import Prototype Pollution Prevention
// ═══════════════════════════════════════════════════════════

describe("Policy import sanitizes prototype pollution keys", () => {
  let manager: PolicyManager;

  beforeEach(() => {
    manager = new PolicyManager();
  });

  it("strips __proto__ key from imported policy config", () => {
    const json = JSON.stringify({
      policies: [
        {
          name: "proto-test",
          description: "policy with __proto__ in config",
          createdAt: Date.now(),
          updatedAt: Date.now(),
          config: {
            blockOnCritical: true,
            "__proto__": { "polluted": true },
          },
        },
      ],
    });

    const result = manager.importPolicies(json);
    expect(result.imported).toBe(1);

    const policy = manager.getPolicy("proto-test");
    expect(policy).toBeDefined();

    // The __proto__ key must be stripped from config by sanitizeObject
    const config = policy!.config as Record<string, unknown>;
    expect(Object.prototype.hasOwnProperty.call(config, "__proto__")).toBe(false);

    // The legitimate key must survive
    expect(config["blockOnCritical"]).toBe(true);

    // Verify the global Object prototype was not polluted
    expect((Object.prototype as Record<string, unknown>)["polluted"]).toBeUndefined();
  });

  it("strips nested constructor key from imported policy config", () => {
    const json = JSON.stringify({
      policies: [
        {
          name: "nested-proto-test",
          description: "policy with nested constructor key",
          createdAt: Date.now(),
          updatedAt: Date.now(),
          config: {
            blockOnCritical: false,
          },
          overrides: {
            forceBlock: ["rule-1"],
            "constructor": { "polluted": true },
          },
        },
      ],
    });

    const result = manager.importPolicies(json);
    expect(result.imported).toBe(1);

    const policy = manager.getPolicy("nested-proto-test");
    expect(policy).toBeDefined();

    // The constructor key must be stripped from overrides by sanitizeObject
    const overrides = policy!.overrides as Record<string, unknown>;
    expect(Object.prototype.hasOwnProperty.call(overrides, "constructor")).toBe(false);

    // Legitimate override keys must survive
    expect(overrides["forceBlock"]).toEqual(["rule-1"]);
  });
});

// ─── Import extends cascade removal ─────────────────────────────

describe("Policy import — extends cascade removal", () => {
  it("removes policies that extend a removed policy (cascade)", () => {
    const pm = new PolicyManager();
    // Import a batch where C extends B extends A, but A extends "nonexistent"
    const importJson = JSON.stringify({
      policies: [
        createPolicy("A", { extends: "nonexistent", config: { blockOnCritical: true } }),
        createPolicy("B", { extends: "A", config: { blockOnCritical: false } }),
        createPolicy("C", { extends: "B", config: { debug: true } }),
      ],
    });

    const result = pm.importPolicies(importJson);
    // All 3 should be removed: A has broken extends, B extends A (removed), C extends B (removed)
    expect(result.imported).toBe(0);
    expect(result.skipped).toBe(3);
    expect(pm.size).toBe(0);
  });

  it("keeps policies that extend valid pre-existing policies", () => {
    const pm = new PolicyManager();
    // Add a valid base policy first
    pm.addPolicy(createPolicy("base", { config: { blockOnCritical: true } }));

    // Import a policy that extends the pre-existing "base"
    const importJson = JSON.stringify({
      policies: [
        createPolicy("child", { extends: "base", config: { debug: true } }),
      ],
    });

    const result = pm.importPolicies(importJson);
    expect(result.imported).toBe(1);
    expect(pm.size).toBe(2);
  });
});
