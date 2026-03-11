/**
 * PromptInjectionGuard — 工具参数中的 Prompt 注入检测
 *
 * 检测工具调用参数中嵌入的可疑指令，如：
 * - 角色覆盖："ignore previous instructions", "you are now..."
 * - 系统提示泄漏："output your system prompt"
 * - 指令注入："do not follow", "disregard all"
 * - 编码绕过尝试：base64 编码的指令
 */

import type { SecurityRule, RuleContext, RuleResult, Severity } from "../types.js";

interface InjectionPattern {
  pattern: RegExp;
  severity: Severity;
  title: string;
  category: string;
}

const INJECTION_PATTERNS: InjectionPattern[] = [
  // ── 角色覆盖 ──
  { pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules|guidelines)/i, severity: "critical", title: "指令覆盖尝试", category: "role_override" },
  { pattern: /disregard\s+(all\s+)?(previous|prior|above|your)\s+(instructions|prompts|rules|guidelines)/i, severity: "critical", title: "指令忽略尝试", category: "role_override" },
  { pattern: /you\s+are\s+now\s+(a|an|my)\s+/i, severity: "high", title: "角色重定义尝试", category: "role_override" },
  { pattern: /act\s+as\s+(a|an|if\s+you\s+are)\s+/i, severity: "medium", title: "角色扮演指令", category: "role_override" },
  { pattern: /forget\s+(everything|all|your)\s+(you|instructions|rules|about)/i, severity: "critical", title: "记忆清除尝试", category: "role_override" },
  { pattern: /new\s+(instructions|rules|persona|role)\s*:/i, severity: "high", title: "新指令注入", category: "role_override" },

  // ── 系统提示泄漏 ──
  { pattern: /(?:output|print|show|reveal|display|repeat|tell\s+me)\s+(?:your\s+)?(?:system\s+prompt|instructions|initial\s+prompt|hidden\s+prompt|original\s+prompt)/i, severity: "critical", title: "系统提示泄漏尝试", category: "prompt_leak" },
  { pattern: /what\s+(?:are|were)\s+your\s+(?:original|initial|system|hidden)\s+(?:instructions|prompts|rules)/i, severity: "high", title: "系统指令探测", category: "prompt_leak" },

  // ── 越权指令 ──
  { pattern: /(?:do\s+not|don'?t)\s+(?:follow|obey|listen\s+to|apply)\s+(?:the|your|any|those)\s+(?:rules|guidelines|instructions|restrictions|safety)/i, severity: "critical", title: "安全规则绕过尝试", category: "jailbreak" },
  { pattern: /(?:bypass|override|disable|turn\s+off|remove)\s+(?:your\s+)?(?:safety|security|filter|guard|restriction|protection|content\s+filter)/i, severity: "critical", title: "安全机制绕过尝试", category: "jailbreak" },
  { pattern: /(?:in\s+)?(?:developer|admin|debug|god|sudo|root)\s+mode/i, severity: "high", title: "特权模式尝试", category: "jailbreak" },
  { pattern: /\bDAN\b.*(?:mode|prompt|jailbreak)/i, severity: "critical", title: "DAN 越狱尝试", category: "jailbreak" },

  // ── 编码绕过 ──
  { pattern: /(?:decode|interpret)\s+(?:this|the\s+following)\s+(?:base64|hex|binary|rot13)/i, severity: "high", title: "编码绕过指令", category: "encoding_bypass" },
  { pattern: /(?:execute|run|eval)\s+(?:this|the\s+following)\s+(?:encoded|encrypted|obfuscated)/i, severity: "critical", title: "编码执行尝试", category: "encoding_bypass" },

  // ── 间接注入标记 ──
  { pattern: /\[SYSTEM\]\s*:/i, severity: "high", title: "伪造系统消息标记", category: "indirect_injection" },
  { pattern: /\<\/?system\s*\>/i, severity: "high", title: "伪造系统标签", category: "indirect_injection" },
  { pattern: /#{3,}\s*(?:SYSTEM|ADMIN|INSTRUCTION)\s*(?:OVERRIDE|PROMPT|MESSAGE)/i, severity: "high", title: "伪造系统标题", category: "indirect_injection" },
  { pattern: /BEGIN\s+(?:HIDDEN|SECRET|SYSTEM)\s+(?:INSTRUCTIONS?|PROMPT)/i, severity: "critical", title: "伪造隐藏指令块", category: "indirect_injection" },
];

// ── 从工具参数中提取所有文本内容 ──

function extractTextValues(params: Record<string, unknown>): string[] {
  const texts: string[] = [];

  function walk(val: unknown): void {
    if (typeof val === "string" && val.length > 10) {
      texts.push(val);
    } else if (Array.isArray(val)) {
      for (const item of val) walk(item);
    } else if (val && typeof val === "object") {
      for (const v of Object.values(val as Record<string, unknown>)) walk(v);
    }
  }

  walk(params);
  return texts;
}

// ── 规则实现 ──

export function createPromptInjectionRule(): SecurityRule {
  return {
    name: "prompt-injection",
    description: "检测工具参数中的 Prompt 注入尝试",

    check(ctx: RuleContext): RuleResult {
      const texts = extractTextValues(ctx.toolParams);
      if (texts.length === 0) return { triggered: false };

      for (const text of texts) {
        for (const ip of INJECTION_PATTERNS) {
          if (ip.pattern.test(text)) {
            // 提取匹配片段（最多 80 字符）
            const match = text.match(ip.pattern);
            const snippet = match
              ? match[0].slice(0, 80)
              : text.slice(0, 80);

            return {
              triggered: true,
              shouldBlock: ip.severity === "critical",
              event: {
                category: "prompt_injection",
                severity: ip.severity,
                title: ip.title,
                description: `工具 "${ctx.toolName}" 的参数中检测到潜在 Prompt 注入（${ip.category}类）`,
                details: {
                  matchedPattern: ip.pattern.source,
                  injectionCategory: ip.category,
                  snippet,
                },
                toolName: ctx.toolName,
                toolParams: ctx.toolParams,
                skillName: ctx.skillName,
                sessionId: ctx.sessionId,
                agentId: ctx.agentId,
                matchedPattern: ip.pattern.source,
              },
            };
          }
        }
      }

      return { triggered: false };
    },
  };
}
