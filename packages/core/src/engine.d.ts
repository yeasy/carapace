/**
 * Carapace Core — 规则评估引擎
 *
 * 按顺序运行所有注册规则，收集结果，
 * 最高严重级别优先，任一 shouldBlock=true 即阻断。
 */
import type { SecurityRule, RuleContext, SecurityEvent, BlockDecision } from "./types.js";
export interface EngineResult {
    triggered: boolean;
    shouldBlock: boolean;
    events: SecurityEvent[];
    blockReason?: string;
}
export declare class RuleEngine {
    private rules;
    addRule(rule: SecurityRule): void;
    removeRule(name: string): void;
    getRules(): readonly SecurityRule[];
    /**
     * 评估所有规则，返回合并结果。
     */
    evaluate(ctx: RuleContext): EngineResult;
    /**
     * 便捷方法：评估并返回 BlockDecision（供 adapter 使用）。
     */
    evaluateForBlock(ctx: RuleContext, blockOnCritical: boolean): {
        decision: BlockDecision;
        events: SecurityEvent[];
    };
}
//# sourceMappingURL=engine.d.ts.map