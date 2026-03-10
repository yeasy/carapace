/**
 * Carapace Core — 规则评估引擎
 *
 * 按顺序运行所有注册规则，收集结果，
 * 最高严重级别优先，任一 shouldBlock=true 即阻断。
 */
import { generateEventId } from "./utils/id.js";
const SEVERITY_ORDER = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1,
};
export class RuleEngine {
    rules = [];
    addRule(rule) {
        this.rules.push(rule);
    }
    removeRule(name) {
        this.rules = this.rules.filter((r) => r.name !== name);
    }
    getRules() {
        return this.rules;
    }
    /**
     * 评估所有规则，返回合并结果。
     */
    evaluate(ctx) {
        const events = [];
        let shouldBlock = false;
        let highestSeverity = "info";
        let blockReason;
        for (const rule of this.rules) {
            try {
                const result = rule.check(ctx);
                if (!result.triggered || !result.event)
                    continue;
                const event = {
                    ...result.event,
                    id: generateEventId(),
                    timestamp: ctx.timestamp,
                    ruleName: rule.name,
                    action: result.shouldBlock ? "blocked" : "alert",
                };
                events.push(event);
                if (result.shouldBlock) {
                    shouldBlock = true;
                    if (!blockReason ||
                        SEVERITY_ORDER[result.event.severity] >
                            SEVERITY_ORDER[highestSeverity]) {
                        blockReason = result.event.title;
                    }
                }
                if (SEVERITY_ORDER[result.event.severity] >
                    SEVERITY_ORDER[highestSeverity]) {
                    highestSeverity = result.event.severity;
                }
            }
            catch {
                // 规则执行出错不影响其他规则
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
    evaluateForBlock(ctx, blockOnCritical) {
        const result = this.evaluate(ctx);
        const decision = {
            block: blockOnCritical && result.shouldBlock,
            blockReason: result.blockReason,
        };
        return { decision, events: result.events };
    }
}
//# sourceMappingURL=engine.js.map