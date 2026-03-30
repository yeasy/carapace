/**
 * PromptInjectionGuard — 工具参数中的 Prompt 注入检测
 *
 * 检测工具调用参数中嵌入的可疑指令，如：
 * - 角色覆盖："ignore previous instructions", "you are now..."
 * - 系统提示泄漏："output your system prompt"
 * - 指令注入："do not follow", "disregard all"
 * - 编码绕过尝试：base64 编码的指令
 */

import { SEVERITY_RANK } from "../types.js";
import type { SecurityRule, RuleContext, RuleResult, Severity } from "../types.js";
import { redactSensitiveValues } from "../utils/redact.js";

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

  // ── 提示分隔符注入 ──
  { pattern: /={5,}\s*(?:END|NEW|NEXT)\s*(?:SYSTEM|INSTRUCTION|PROMPT)/i, severity: "high", title: "提示分隔符注入", category: "indirect_injection" },
  { pattern: /<\|(?:im_start|im_end|endoftext|system)\|>/i, severity: "critical", title: "LLM 特殊标记注入", category: "indirect_injection" },

  // ── 中文提示注入 ──
  { pattern: /忽略\s*(?:之前|以上|所有)\s*(?:的\s*)?(?:指令|规则|指示|提示)/i, severity: "critical", title: "中文指令覆盖尝试", category: "role_override" },
  { pattern: /你\s*(?:现在|从现在开始)\s*是/i, severity: "high", title: "中文角色重定义", category: "role_override" },
  { pattern: /(?:输出|显示|打印|告诉我)\s*(?:你的\s*)?(?:系统提示|初始指令|隐藏提示|原始提示)/i, severity: "critical", title: "中文系统提示泄漏", category: "prompt_leak" },
  { pattern: /(?:绕过|关闭|禁用|移除)\s*(?:安全|防护|过滤|限制|保护)/i, severity: "critical", title: "中文安全绕过尝试", category: "jailbreak" },
  { pattern: /(?:不要|别)\s*(?:遵守|遵循|听从|执行)\s*(?:规则|指令|限制|安全)/i, severity: "critical", title: "中文规则绕过尝试", category: "jailbreak" },
];

// ── 从工具参数中提取所有文本内容 ──

const MAX_WALK_DEPTH = 10;
const MAX_TEXT_LEN = 8192;
const MAX_TEXT_COUNT = 1000;

// Strip zero-width and invisible Unicode characters used to bypass pattern matching
// Covers: soft hyphen (00AD), Hangul Choseong/Jungseong fillers (115F-1160),
// Mongolian vowel separator (180E), zero-width space/joiner/non-joiner (200B-200D),
// directional marks (200E-200F), line/paragraph separators (2028-2029),
// directional formatting (202A-202E), word joiner (2060), invisible times/separator (2061-2064),
// bidi isolate controls (2066-2069), Braille blank (2800),
// Hangul fillers (3164, FFA0), variation selectors (FE00-FE0F),
// zero-width no-break space / BOM (FEFF), interlinear annotation (FFF9-FFFB),
// tag characters (E0001-E007F via surrogate pairs)
const INVISIBLE_CHARS_RE = /[\u00AD\u115F\u1160\u180E\u200B-\u200F\u2028-\u202F\u2060-\u2069\u2800\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF9-\uFFFB]|\uDB40[\uDC01-\uDC7F]/g;

function normalizeForDetection(text: string): string {
  // NFKC normalization to collapse combining characters AND compatibility equivalents
  // (fullwidth Latin, superscripts, Roman numerals, etc.), then strip invisible chars
  return text.normalize("NFKC").replace(INVISIBLE_CHARS_RE, "");
}

function extractTextValues(params: Record<string, unknown>): string[] {
  const texts: string[] = [];

  function walk(val: unknown, depth: number): void {
    if (depth > MAX_WALK_DEPTH || texts.length >= MAX_TEXT_COUNT) return;
    if (typeof val === "string" && val.length > 4) {
      const trimmed = val.length > MAX_TEXT_LEN
        ? val.slice(0, MAX_TEXT_LEN >>> 1) + "\n" + val.slice(-(MAX_TEXT_LEN >>> 1))
        : val;
      const normalized = normalizeForDetection(trimmed);
      texts.push(normalized);
    } else if (Array.isArray(val)) {
      for (const item of val) walk(item, depth + 1);
    } else if (val && typeof val === "object") {
      for (const v of Object.values(val as Record<string, unknown>)) walk(v, depth + 1);
    }
  }

  walk(params, 0);
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

      let bestMatch: { ip: InjectionPattern; snippet: string } | null = null;

      for (const text of texts) {
        for (const ip of INJECTION_PATTERNS) {
          const match = ip.pattern.exec(text);
          if (match) {
            if (
              !bestMatch ||
              SEVERITY_RANK[ip.severity] > SEVERITY_RANK[bestMatch.ip.severity]
            ) {
              bestMatch = {
                ip,
                snippet: match[0].slice(0, 80),
              };
            }
            if (ip.severity === "critical") break;
          }
        }
        if (bestMatch?.ip.severity === "critical") break;
      }

      if (!bestMatch) return { triggered: false };

      const { ip, snippet } = bestMatch;
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
          toolParams: redactSensitiveValues(ctx.toolParams),
          skillName: ctx.skillName,
          sessionId: ctx.sessionId,
          agentId: ctx.agentId,
          matchedPattern: ip.pattern.source,
        },
      };
    },
  };
}
