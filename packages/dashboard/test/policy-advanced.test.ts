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

  it("imports policies correctly", () => {
    const policy1 = createPolicy("import-1");
    const policy2 = createPolicy("import-2");

    const json = JSON.stringify({
      policies: [policy1, policy2],
    });

    const count = manager.importPolicies(json);

    expect(count).toBe(2);
    expect(manager.size).toBe(2);
    expect(manager.getPolicy("import-1")).toBeDefined();
    expect(manager.getPolicy("import-2")).toBeDefined();
  });

  it("imports policies and restores active policy", () => {
    const policy = createPolicy("imported");

    const json = JSON.stringify({
      policies: [policy],
      activePolicy: "imported",
    });

    manager.importPolicies(json);

    expect(manager.getActivePolicyName()).toBe("imported");
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
    manager2.importPolicies(exported);

    const restored = manager2.getPolicy("original");
    expect(restored?.config.blockOnCritical).toBe(true);
    expect(restored?.config.maxToolCallsPerMinute).toBe(42);
    expect(restored?.overrides?.forceBlock).toContain("rule-x");
    expect(manager2.getActivePolicyName()).toBe("original");
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

  it("handles policy with very long name", () => {
    const longName = "x".repeat(1000);
    const policy = createPolicy(longName);
    manager.addPolicy(policy);

    expect(manager.getPolicy(longName)).toBeDefined();
  });

  it("handles policy with special characters in name", () => {
    const specialName = "policy-with-$pecial_ch@rs!";
    const policy = createPolicy(specialName);
    manager.addPolicy(policy);

    expect(manager.getPolicy(specialName)).toBeDefined();
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

  it("handles large inheritance chains", () => {
    let current = "level-0";
    const policies = [createPolicy(current)];

    for (let i = 1; i < 20; i++) {
      const next = `level-${i}`;
      policies.push(
        createPolicy(next, { extends: current })
      );
      current = next;
    }

    policies.forEach((p) => manager.addPolicy(p));

    const resolved = manager.resolvePolicy("level-19");
    expect(resolved.name).toBe("level-19");
  });
});
