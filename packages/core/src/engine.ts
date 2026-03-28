/**
 * Carapace Core — 规则评估引擎
 *
 * 按顺序运行所有注册规则，收集结果，
 * 最高严重级别优先，任一 shouldBlock=true 即阻断。
 */

import { generateEventId } from "./utils/id.js";
import { SEVERITY_RANK } from "./types.js";
import type {
  SecurityRule,
  RuleContext,
  SecurityEvent,
  BlockDecision,
  Severity,
} from "./types.js";

export interface EngineResult {
  triggered: boolean;
  shouldBlock: boolean;
  events: SecurityEvent[];
  blockReason?: string;
}

export class RuleEngine {
  private rules: SecurityRule[] = [];
  private trustedSkills: Set<string> = new Set();

  addRule(rule: SecurityRule): void {
    this.rules.push(rule);
  }

  removeRule(name: string): void {
    this.rules = this.rules.filter((r) => r.name !== name);
  }

  getRules(): readonly SecurityRule[] {
    return this.rules;
  }

  /**
   * 设置受信 skill 列表。来自这些 skill 的工具调用将跳过规则评估。
   */
  setTrustedSkills(skills: string[]): void {
    this.trustedSkills = new Set(skills);
  }

  getTrustedSkills(): ReadonlySet<string> {
    return this.trustedSkills;
  }

  /**
   * 评估所有规则，返回合并结果。
   * 如果 ctx.skillName 在 trustedSkills 中，跳过评估。
   */
  evaluate(ctx: RuleContext): EngineResult {
    // 受信 skill 跳过规则评估
    if (ctx.skillName && this.trustedSkills.has(ctx.skillName)) {
      return { triggered: false, shouldBlock: false, events: [] };
    }

    const events: SecurityEvent[] = [];
    let shouldBlock = false;
    let highestSeverity: Severity = "info";
    let highestBlockSeverity: Severity = "info";
    let blockReason: string | undefined;

    for (const rule of this.rules) {
      try {
        const result = rule.check(ctx);
        if (!result.triggered || !result.event) continue;

        const event: SecurityEvent = {
          ...result.event,
          id: generateEventId(),
          timestamp: ctx.timestamp,
          ruleName: rule.name,
          action: result.shouldBlock ? "blocked" : "alert",
        };

        events.push(event);

        if (result.shouldBlock) {
          shouldBlock = true;
          if (
            !blockReason ||
            SEVERITY_RANK[result.event.severity] >
              SEVERITY_RANK[highestBlockSeverity]
          ) {
            blockReason = result.event.title;
            highestBlockSeverity = result.event.severity;
          }
        }

        if (
          SEVERITY_RANK[result.event.severity] >
          SEVERITY_RANK[highestSeverity]
        ) {
          highestSeverity = result.event.severity;
        }
      } catch (err) {
        process.stderr.write(
          `[CARAPACE] rule "${rule.name}" threw: ${err instanceof Error ? err.message : String(err)}\n`
        );
      }
    }

    return {
      triggered: events.length > 0,
      shouldBlock,
      events,
      blockReason,
    };
  }

  /**
   * 便捷方法：评估并返回 BlockDecision（供 adapter 使用）。
   */
  evaluateForBlock(
    ctx: RuleContext,
    blockOnCritical: boolean
  ): { decision: BlockDecision; events: SecurityEvent[] } {
    const result = this.evaluate(ctx);

    const decision: BlockDecision = {
      block: blockOnCritical && result.shouldBlock,
      blockReason: result.blockReason,
    };

    return { decision, events: result.events };
  }
}
