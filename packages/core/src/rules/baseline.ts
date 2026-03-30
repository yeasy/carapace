/**
 * BaselineTracker — 逐 Skill 行为基线建模与偏离检测
 *
 * 为每个 skill 建立工具调用行为基线：
 * - 记录每个 skill 常用的工具集合
 * - 统计各工具的调用频率
 * - 当 skill 调用从未见过的工具时，触发 baseline_drift 告警
 * - 当 skill 的工具使用模式显著偏离基线时告警
 *
 * 基线在运行时动态构建（学习阶段），不持久化。
 * 可配合 session_start/session_end 进行生命周期管理。
 */

import type { SecurityRule, RuleContext, RuleResult, Severity } from "../types.js";
import { redactSensitiveValues } from "../utils/redact.js";

interface SkillProfile {
  /** 该 skill 已见过的工具 -> 调用次数 */
  toolCounts: Map<string, number>;
  /** 总调用次数 */
  totalCalls: number;
  /** 是否已完成学习阶段 */
  learned: boolean;
  /** Number of unique tools known when learning completed */
  learnedToolCount: number;
  /** Number of novel tools discovered after learning phase */
  postLearningNovelCount: number;
}

export interface BaselineConfig {
  /** 学习阶段的最小调用次数（之后才会触发偏离检测），默认 20 */
  learningThreshold?: number;
  /** 允许的最大新工具比例（0-1），超过时告警，默认 0.3 */
  maxNoveltyRatio?: number;
}

export class BaselineTracker {
  private profiles = new Map<string, SkillProfile>();
  private learningThreshold: number;
  private maxNoveltyRatio: number;
  private static readonly MAX_PROFILES = 1000;

  constructor(config?: BaselineConfig) {
    this.learningThreshold = config?.learningThreshold ?? 20;
    this.maxNoveltyRatio = config?.maxNoveltyRatio ?? 0.3;
  }

  /**
   * 记录一次工具调用，更新基线。
   * @returns 该工具是否是该 skill 首次使用的新工具
   */
  recordCall(skillName: string, toolName: string): { isNovel: boolean; profile: SkillProfile } {
    if (!this.profiles.has(skillName)) {
      // Evict least-used profile if at capacity
      if (this.profiles.size >= BaselineTracker.MAX_PROFILES) {
        let minKey: string | null = null;
        let minCalls = Infinity;
        for (const [key, p] of this.profiles) {
          if (p.totalCalls < minCalls) {
            minCalls = p.totalCalls;
            minKey = key;
          }
        }
        if (minKey) this.profiles.delete(minKey);
      }
      this.profiles.set(skillName, {
        toolCounts: new Map(),
        totalCalls: 0,
        learned: false,
        learnedToolCount: 0,
        postLearningNovelCount: 0,
      });
    }

    const profile = this.profiles.get(skillName)!;
    const isNovel = !profile.toolCounts.has(toolName);

    profile.toolCounts.set(toolName, (profile.toolCounts.get(toolName) ?? 0) + 1);
    profile.totalCalls++;

    // 检查是否已完成学习阶段
    if (!profile.learned && profile.totalCalls >= this.learningThreshold) {
      profile.learned = true;
      profile.learnedToolCount = profile.toolCounts.size;
    }

    // Track novel tools discovered after learning phase
    if (profile.learned && isNovel) {
      profile.postLearningNovelCount++;
    }

    return { isNovel, profile };
  }

  /**
   * 获取 skill 的基线概况
   */
  getProfile(skillName: string): SkillProfile | undefined {
    return this.profiles.get(skillName);
  }

  /**
   * 重置某个 skill 的基线
   */
  resetProfile(skillName: string): void {
    this.profiles.delete(skillName);
  }

  /**
   * 重置所有基线
   */
  resetAll(): void {
    this.profiles.clear();
  }

  /**
   * 判断 skill 是否仍在学习阶段
   */
  isLearning(skillName: string): boolean {
    const profile = this.profiles.get(skillName);
    return !profile || !profile.learned;
  }

  get profileCount(): number {
    return this.profiles.size;
  }

  get threshold(): number {
    return this.learningThreshold;
  }

  get noveltyRatio(): number {
    return this.maxNoveltyRatio;
  }
}

// ── 规则实现 ──

export function createBaselineDriftRule(config?: BaselineConfig): {
  rule: SecurityRule;
  tracker: BaselineTracker;
} {
  const tracker = new BaselineTracker(config);

  const rule: SecurityRule = {
    name: "baseline-drift",
    description: "检测 Skill 行为偏离基线",

    check(ctx: RuleContext): RuleResult {
      const skillName = ctx.skillName;
      if (!skillName) return { triggered: false };

      const { isNovel, profile } = tracker.recordCall(skillName, ctx.toolName);

      // 仍在学习阶段，只记录不告警
      if (!profile.learned) {
        return { triggered: false };
      }

      // 学习完成后，检测新工具调用
      if (isNovel) {
        // Compute ratio of post-learning novel tools to baseline tool count.
        // This escalates severity as more novel tools are discovered.
        const baselineTools = profile.learnedToolCount || 1;
        const noveltyRatio = profile.postLearningNovelCount / baselineTools;

        let severity: Severity = "medium";
        if (noveltyRatio > tracker.noveltyRatio) {
          severity = "high";
        }

        return {
          triggered: true,
          shouldBlock: false,
          event: {
            category: "baseline_drift",
            severity,
            title: `Skill "${skillName}" 调用了未见过的工具`,
            description: `Skill "${skillName}" 首次调用工具 "${ctx.toolName}"，偏离已建立的行为基线`,
            details: {
              skillName,
              novelTool: ctx.toolName,
              knownTools: [...profile.toolCounts.keys()].filter((t) => t !== ctx.toolName),
              totalCalls: profile.totalCalls,
              uniqueTools: profile.toolCounts.size,
            },
            toolName: ctx.toolName,
            toolParams: redactSensitiveValues(ctx.toolParams),
            skillName: ctx.skillName,
            sessionId: ctx.sessionId,
            agentId: ctx.agentId,
          },
        };
      }

      return { triggered: false };
    },
  };

  return { rule, tracker };
}
