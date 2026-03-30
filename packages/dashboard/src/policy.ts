/**
 * 团队策略管理 — 集中管理多 Agent 的安全策略
 *
 * 支持:
 * - 多策略定义（按团队/环境/场景分组）
 * - 策略继承（child extends parent）
 * - 运行时策略切换
 * - 策略导入/导出（JSON 格式）
 */

import { type CarapaceConfig, loadYamlRules } from "@carapace/core";

const DANGEROUS_PROTO_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/** Deep-clone an object, stripping prototype pollution keys */
function sanitizeObject<T>(obj: T): T {
  if (obj === null || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(sanitizeObject) as unknown as T;
  const clean: Record<string, unknown> = {};
  for (const key of Object.keys(obj as Record<string, unknown>)) {
    if (!DANGEROUS_PROTO_KEYS.has(key)) {
      clean[key] = sanitizeObject((obj as Record<string, unknown>)[key]);
    }
  }
  return clean as T;
}

// ── 策略定义 ──

export interface PolicyDefinition {
  /** 策略唯一名称 */
  name: string;
  /** 策略描述 */
  description: string;
  /** 父策略名称（用于继承） */
  extends?: string;
  /** 创建时间 */
  createdAt: number;
  /** 最后修改时间 */
  updatedAt: number;
  /** 创建者 */
  createdBy?: string;

  /** Carapace 核心配置 */
  config: CarapaceConfig;

  /** YAML 自定义规则（字符串） */
  yamlRules?: string;

  /** 策略级别的覆盖 */
  overrides?: {
    /** 强制阻断的规则名列表 */
    forceBlock?: string[];
    /** 禁用的规则名列表 */
    disabledRules?: string[];
    /** 额外的受信 Skill */
    additionalTrustedSkills?: string[];
  };
}

// ── 策略管理器 ──

export class PolicyManager {
  private policies = new Map<string, PolicyDefinition>();
  private activePolicy: string | null = null;

  /**
   * 添加策略
   */
  addPolicy(policy: PolicyDefinition): void {
    if (!policy.name || typeof policy.name !== "string" || !/^[\w\-.]{1,100}$/.test(policy.name)) {
      throw new Error("Invalid policy name: must be 1-100 chars using letters, digits, hyphens, underscores, or dots");
    }
    policy.updatedAt = Date.now();
    this.policies.set(policy.name, sanitizeObject(policy));
  }

  /**
   * 获取策略
   */
  getPolicy(name: string): PolicyDefinition | undefined {
    return this.policies.get(name);
  }

  /**
   * 删除策略
   */
  removePolicy(name: string): boolean {
    if (this.activePolicy === name) {
      this.activePolicy = null;
    }
    return this.policies.delete(name);
  }

  /**
   * 列出所有策略
   */
  listPolicies(): PolicyDefinition[] {
    return Array.from(this.policies.values());
  }

  /**
   * 设置活跃策略
   */
  setActivePolicy(name: string): void {
    if (!this.policies.has(name)) {
      throw new Error(`Policy "${name}" not found`);
    }
    this.activePolicy = name;
  }

  /**
   * 获取活跃策略名称
   */
  getActivePolicyName(): string | null {
    return this.activePolicy;
  }

  /**
   * 解析策略（含继承链），返回最终合并的配置
   */
  resolvePolicy(name: string): ResolvedPolicy {
    const chain = this.buildInheritanceChain(name);
    return this.mergeChain(chain);
  }

  /**
   * 解析当前活跃策略
   */
  resolveActivePolicy(): ResolvedPolicy | null {
    if (!this.activePolicy) return null;
    return this.resolvePolicy(this.activePolicy);
  }

  /**
   * 导出所有策略为 JSON
   */
  exportPolicies(): string {
    const policies = this.listPolicies();
    return JSON.stringify(
      {
        version: "1.0",
        exportedAt: new Date().toISOString(),
        activePolicy: this.activePolicy,
        policies,
      },
      null,
      2
    );
  }

  /**
   * 从 JSON 导入策略
   *
   * Returns import summary with count of imported and skipped policies.
   * Does NOT auto-activate any policy — caller should explicitly setActivePolicy if desired.
   */
  importPolicies(json: string): ImportResult {
    const data = JSON.parse(json);
    if (!data || typeof data !== "object" || !Array.isArray(data.policies)) {
      throw new Error("Invalid import format: expected { policies: [...] }");
    }
    let imported = 0;
    let skipped = 0;
    const importedNames = new Set<string>();
    for (const policy of data.policies as PolicyDefinition[]) {
      if (!policy.name || typeof policy.name !== "string") { skipped++; continue; }
      if (policy.config !== undefined && (typeof policy.config !== "object" || policy.config === null || Array.isArray(policy.config))) { skipped++; continue; }

      // Validate config fields
      if (policy.config) {
        if ("trustedSkills" in policy.config && policy.config.trustedSkills !== undefined) {
          if (!Array.isArray(policy.config.trustedSkills) || !policy.config.trustedSkills.every((s: unknown) => typeof s === "string")) {
            skipped++; continue;
          }
        }
        if ("blockOnCritical" in policy.config && policy.config.blockOnCritical !== undefined) {
          if (typeof policy.config.blockOnCritical !== "boolean") {
            skipped++; continue;
          }
        }
      }

      // Validate override arrays contain only strings
      if (policy.overrides) {
        const arrayFields = ["forceBlock", "disabledRules", "additionalTrustedSkills"] as const;
        let overrideInvalid = false;
        for (const field of arrayFields) {
          const arr = policy.overrides[field];
          if (arr !== undefined) {
            if (!Array.isArray(arr) || !arr.every((v: unknown) => typeof v === "string")) {
              overrideInvalid = true;
              break;
            }
          }
        }
        if (overrideInvalid) { skipped++; continue; }
      }

      // Validate YAML rules to prevent ReDoS and malformed patterns
      if (typeof policy.yamlRules === "string" && policy.yamlRules.trim()) {
        try {
          loadYamlRules(policy.yamlRules);
        } catch {
          skipped++; continue;
        }
      }

      try {
        this.addPolicy(policy);
        importedNames.add(policy.name);
        imported++;
      } catch {
        skipped++;
      }
    }
    // Validate `extends` references — iterate until stable to handle cascading removals
    // (e.g., A extends B, B extends C — if C is removed, B becomes invalid, then A becomes invalid)
    let changed = true;
    while (changed) {
      changed = false;
      const toRemove: string[] = [];
      for (const name of importedNames) {
        const policy = this.policies.get(name);
        if (policy?.extends && !this.policies.has(policy.extends)) {
          process.stderr.write(`[carapace] Warning: Imported policy "${name}" extends unknown policy "${policy.extends}", removing it\n`);
          toRemove.push(name);
        }
      }
      for (const name of toRemove) {
        this.policies.delete(name);
        importedNames.delete(name);
        imported--;
        skipped++;
        changed = true;
      }
    }

    return {
      imported,
      skipped,
      activePolicy: data.activePolicy ?? null,
    };
  }

  /**
   * 获取策略数量
   */
  get size(): number {
    return this.policies.size;
  }

  // ── 内部方法 ──

  private buildInheritanceChain(name: string): PolicyDefinition[] {
    const chain: PolicyDefinition[] = [];
    const visited = new Set<string>();
    const MAX_DEPTH = 10;
    let current: string | undefined = name;

    while (current) {
      if (visited.has(current)) {
        throw new Error(`Circular policy inheritance detected: ${current}`);
      }
      if (chain.length >= MAX_DEPTH) {
        throw new Error(`Policy inheritance chain too deep (max ${MAX_DEPTH})`);
      }
      visited.add(current);

      const policy = this.policies.get(current);
      if (!policy) {
        throw new Error(`Policy "${current}" not found`);
      }
      chain.unshift(policy); // 父策略在前
      current = policy.extends;
    }

    return chain;
  }

  private mergeChain(chain: PolicyDefinition[]): ResolvedPolicy {
    const result: ResolvedPolicy = {
      name: chain[chain.length - 1].name,
      description: chain[chain.length - 1].description,
      config: {},
      yamlRules: [],
      forceBlock: [],
      disabledRules: [],
      trustedSkills: [],
    };

    const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);
    for (const policy of chain) {
      // 合并 config（后者覆盖前者），过滤危险键防止原型污染
      if (policy.config) {
        for (const [key, value] of Object.entries(policy.config)) {
          if (!DANGEROUS_KEYS.has(key)) {
            (result.config as Record<string, unknown>)[key] = value;
          }
        }
      }

      // 合并 trustedSkills（仅接受字符串数组）
      if (policy.config && Array.isArray(policy.config.trustedSkills)) {
        for (const skill of policy.config.trustedSkills) {
          if (typeof skill === "string") {
            result.trustedSkills.push(skill);
          }
        }
      }

      // 收集 YAML 规则
      if (policy.yamlRules) {
        result.yamlRules.push(policy.yamlRules);
      }

      // 合并 overrides
      if (policy.overrides) {
        if (policy.overrides.forceBlock) {
          result.forceBlock.push(...policy.overrides.forceBlock);
        }
        if (policy.overrides.disabledRules) {
          result.disabledRules.push(...policy.overrides.disabledRules);
        }
        if (policy.overrides.additionalTrustedSkills) {
          result.trustedSkills.push(...policy.overrides.additionalTrustedSkills);
        }
      }
    }

    // 去重
    result.forceBlock = [...new Set(result.forceBlock)];
    result.disabledRules = [...new Set(result.disabledRules)];
    result.trustedSkills = [...new Set(result.trustedSkills)];
    result.config.trustedSkills = result.trustedSkills;

    return result;
  }
}

export interface ImportResult {
  /** Number of policies successfully imported */
  imported: number;
  /** Number of policies skipped due to validation failures */
  skipped: number;
  /** The activePolicy value from the import data (not auto-applied) */
  activePolicy: string | null;
}

export interface ResolvedPolicy {
  name: string;
  description: string;
  config: CarapaceConfig;
  yamlRules: string[];
  forceBlock: string[];
  disabledRules: string[];
  trustedSkills: string[];
}

// ── 预定义策略模板 ──

export const POLICY_TEMPLATES = {
  /** 宽松策略：仅告警，不阻断 */
  permissive: {
    name: "permissive",
    description: "宽松策略：仅告警，不阻断任何操作",
    config: {
      blockOnCritical: false,
      debug: false,
    },
  } as Omit<PolicyDefinition, "createdAt" | "updatedAt">,

  /** 标准策略：阻断严重威胁 */
  standard: {
    name: "standard",
    description: "标准策略：自动阻断 critical 级别威胁",
    config: {
      blockOnCritical: true,
      maxToolCallsPerMinute: 60,
      enableBaseline: true,
    },
  } as Omit<PolicyDefinition, "createdAt" | "updatedAt">,

  /** 严格策略：最大安全性 */
  strict: {
    name: "strict",
    description: "严格策略：阻断所有威胁，启用全部检测，限速 30 次/分钟",
    config: {
      blockOnCritical: true,
      maxToolCallsPerMinute: 30,
      enableBaseline: true,
    },
    overrides: {
      forceBlock: [
        "exec-guard",
        "path-guard",
        "network-guard",
        "prompt-injection",
        "data-exfil",
      ],
    },
  } as Omit<PolicyDefinition, "createdAt" | "updatedAt">,
};
