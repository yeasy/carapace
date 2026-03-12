/**
 * 团队策略管理 — 集中管理多 Agent 的安全策略
 *
 * 支持:
 * - 多策略定义（按团队/环境/场景分组）
 * - 策略继承（child extends parent）
 * - 运行时策略切换
 * - 策略导入/导出（JSON 格式）
 */

import type { CarapaceConfig } from "@carapace/core";

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
    policy.updatedAt = Date.now();
    this.policies.set(policy.name, policy);
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
   */
  importPolicies(json: string): number {
    const data = JSON.parse(json) as {
      policies: PolicyDefinition[];
      activePolicy?: string;
    };
    let count = 0;
    for (const policy of data.policies) {
      this.addPolicy(policy);
      count++;
    }
    if (data.activePolicy && this.policies.has(data.activePolicy)) {
      this.activePolicy = data.activePolicy;
    }
    return count;
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
    let current: string | undefined = name;

    while (current) {
      if (visited.has(current)) {
        throw new Error(`Circular policy inheritance detected: ${current}`);
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

    for (const policy of chain) {
      // 合并 config（后者覆盖前者）
      result.config = { ...result.config, ...policy.config };

      // 合并 trustedSkills
      if (policy.config.trustedSkills) {
        result.trustedSkills.push(...policy.config.trustedSkills);
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
