/**
 * YAML 自定义规则加载器
 *
 * 允许用户通过 YAML 文件定义安全规则，无需编写 TypeScript 代码。
 *
 * YAML 格式：
 * ```yaml
 * name: my-custom-rule
 * description: 检测自定义危险模式
 * severity: high
 * category: exec_danger
 * shouldBlock: true
 *
 * match:
 *   toolName: bash          # 可选：匹配工具名（精确或正则）
 *   params:                 # 匹配参数中的模式
 *     command:
 *       - "rm\\s+-rf\\s+/"
 *       - "drop\\s+database"
 *     url:
 *       - "evil\\.com"
 *   any_param:              # 匹配任意参数值中的模式
 *     - "password"
 *     - "secret"
 * ```
 */

import type {
  SecurityRule,
  RuleContext,
  RuleResult,
  Severity,
  EventCategory,
} from "../types.js";
import { isRedosSafe } from "../utils/regex.js";
import { redactSensitiveValues } from "../utils/redact.js";

// ── YAML 规则定义结构 ──

export interface YamlRuleDefinition {
  name: string;
  description: string;
  severity: Severity;
  category: EventCategory;
  shouldBlock?: boolean;

  match: {
    /** 匹配工具名（字符串精确匹配或正则） */
    toolName?: string;
    /** 匹配指定参数中的模式（key → 正则数组） */
    params?: Record<string, string[]>;
    /** 匹配任意参数值中的模式 */
    any_param?: string[];
  };
}

// ── YAML 解析器（轻量级，无外部依赖） ──

const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/** Strip surrounding quotes only when they match (both double or both single) */
function stripQuotes(s: string): string {
  if (s.length >= 2 && ((s[0] === '"' && s[s.length - 1] === '"') || (s[0] === "'" && s[s.length - 1] === "'"))) {
    return s.slice(1, -1);
  }
  return s;
}

const MAX_YAML_INPUT = 1_048_576; // 1MB
const MAX_YAML_LINES = 10_000;
const MAX_YAML_DEPTH = 20;
const MAX_KEY_LEN = 200;
const MAX_VALUE_LEN = 10_000;

export function parseSimpleYaml(text: string): Record<string, unknown> {
  if (text.length > MAX_YAML_INPUT) {
    throw new Error(`YAML input too large (${text.length} bytes, max ${MAX_YAML_INPUT})`);
  }
  const result: Record<string, unknown> = {};
  const lines = text.split("\n");
  if (lines.length > MAX_YAML_LINES) {
    throw new Error(`YAML input too many lines (${lines.length}, max ${MAX_YAML_LINES})`);
  }

  // Stack tracks parent objects with their indentation level and last key set
  const stack: { indent: number; obj: Record<string, unknown>; lastKey?: string }[] = [
    { indent: -1, obj: result },
  ];

  function currentParent() {
    return stack[stack.length - 1];
  }

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // 跳过空行和注释
    if (!line.trim() || line.trim().startsWith("#")) continue;

    // 数组项: "  - value"
    const arrMatch = line.match(/^(\s*)-\s+(.*)/);
    if (arrMatch) {
      const indent = arrMatch[1].length;
      const value = stripQuotes(arrMatch[2].trim());

      // Pop to find the object that owns this array
      while (stack.length > 1 && currentParent().indent >= indent) {
        stack.pop();
      }

      const parent = currentParent();
      const key = parent.lastKey;
      if (key && DANGEROUS_KEYS.has(key)) continue;
      if (key) {
        if (!Array.isArray(parent.obj[key])) {
          parent.obj[key] = [];
        }
        (parent.obj[key] as unknown[]).push(value);
      }
      continue;
    }

    const match = line.match(/^(\s*)([\w-]+):\s*(.*)/);
    if (!match) continue;

    const indent = match[1].length;
    const key = match[2];
    if (DANGEROUS_KEYS.has(key)) continue;
    if (key.length > MAX_KEY_LEN) continue;
    let value: string | undefined = match[3].trim();

    // 弹出缩进层级
    while (stack.length > 1 && currentParent().indent >= indent) {
      stack.pop();
    }

    const parent = currentParent();

    if (!value || value === "") {
      // Check if next non-empty line is an array item at deeper indent
      const nextContentLine = peekNextContent(lines, i + 1);
      if (nextContentLine && /^\s*-\s+/.test(nextContentLine)) {
        // This key will hold an array, initialize it
        parent.obj[key] = [];
        parent.lastKey = key;
        // Don't push a new stack level — array items will use parent.lastKey
      } else {
        // Sub-object
        if (stack.length >= MAX_YAML_DEPTH) {
          throw new Error(`YAML nesting too deep (max ${MAX_YAML_DEPTH})`);
        }
        const child: Record<string, unknown> = {};
        parent.obj[key] = child;
        parent.lastKey = key;
        stack.push({ indent, obj: child });
      }
    } else {
      // 移除匹配的引号
      value = stripQuotes(value);
      // Truncate excessively long values
      if (value.length > MAX_VALUE_LEN) value = value.slice(0, MAX_VALUE_LEN);
      // 类型转换
      if (value === "true") parent.obj[key] = true;
      else if (value === "false") parent.obj[key] = false;
      else if (/^-?\d+$/.test(value) && value.length <= 15) parent.obj[key] = parseInt(value, 10);
      else if (/^-?\d+\.\d+$/.test(value) && value.length <= 20) parent.obj[key] = parseFloat(value);
      else parent.obj[key] = value;
      parent.lastKey = key;
    }
  }

  return result;
}

function peekNextContent(lines: string[], from: number): string | null {
  for (let i = from; i < lines.length; i++) {
    const trimmed = lines[i].trim();
    if (trimmed && !trimmed.startsWith("#")) return lines[i];
  }
  return null;
}

// ── 从 YAML 定义构建 SecurityRule ──

export function createYamlRule(def: YamlRuleDefinition): SecurityRule {
  // 预编译所有正则
  const toolNameRegex = def.match.toolName
    ? safeRegex(def.match.toolName)
    : null;

  const paramPatterns = new Map<string, RegExp[]>();
  if (def.match.params) {
    for (const [paramKey, patterns] of Object.entries(def.match.params)) {
      const regexes = patterns.map((p) => safeRegex(p)).filter(Boolean) as RegExp[];
      if (regexes.length > 0) paramPatterns.set(paramKey, regexes);
    }
  }

  const anyParamPatterns = (def.match.any_param ?? [])
    .map((p) => safeRegex(p))
    .filter(Boolean) as RegExp[];

  // A rule with only toolName and no param patterns should trigger on toolName match alone
  const hasParamPatterns = paramPatterns.size > 0 || anyParamPatterns.length > 0;

  return {
    name: def.name,
    description: def.description,
    check(ctx: RuleContext): RuleResult {
      // 工具名匹配
      if (toolNameRegex && !toolNameRegex.test(ctx.toolName)) {
        return { triggered: false };
      }

      // 指定参数匹配
      for (const [paramKey, regexes] of paramPatterns) {
        const paramValue = ctx.toolParams[paramKey];
        if (paramValue === undefined) continue;
        const strVal = String(paramValue);
        for (const rx of regexes) {
          if (rx.test(strVal)) {
            return buildResult(def, ctx, paramKey, rx.source);
          }
        }
      }

      // 任意参数匹配
      if (anyParamPatterns.length > 0) {
        const matched = matchAnyParam(ctx.toolParams, anyParamPatterns);
        if (matched) {
          return buildResult(def, ctx, matched.paramKey, matched.pattern);
        }
      }

      // If only toolName was specified (no param patterns), trigger on toolName match
      if (toolNameRegex && !hasParamPatterns) {
        return buildResult(def, ctx, "toolName", toolNameRegex.source);
      }

      return { triggered: false };
    },
  };
}

// ── 从 YAML 文本直接构建规则 ──

export function loadYamlRules(yamlText: string): SecurityRule[] {
  const rules: SecurityRule[] = [];

  // 支持多文档（--- 分隔）
  const documents = yamlText.split(/^---\s*$/m);

  for (const doc of documents) {
    if (!doc.trim()) continue;
    try {
      const parsed = parseSimpleYaml(doc);
      const def = validateYamlRuleDef(parsed);
      if (def) {
        rules.push(createYamlRule(def));
      } else {
        process.stderr.write(`[carapace] YAML rule validation failed: rule definition is invalid or missing required fields\n`);
      }
    } catch (err) {
      process.stderr.write(`[carapace] YAML rule parse error: ${err instanceof Error ? err.message : String(err)}\n`);
    }
  }

  return rules;
}

// ── 内部工具函数 ──

function safeRegex(pattern: string): RegExp | null {
  try {
    if (!isRedosSafe(pattern)) {
      process.stderr.write(`[carapace/yaml-rule] 拒绝可能导致 ReDoS 的正则模式: "${pattern}"\n`);
      return null;
    }
    return new RegExp(pattern, "i");
  } catch {
    return null;
  }
}

function buildResult(
  def: YamlRuleDefinition,
  ctx: RuleContext,
  paramKey: string,
  pattern: string
): RuleResult {
  return {
    triggered: true,
    shouldBlock: def.shouldBlock ?? false,
    event: {
      category: def.category,
      severity: def.severity,
      title: `[${def.name}] ${def.description}`,
      description: `自定义规则匹配: ${paramKey} 匹配模式 /${pattern}/`,
      details: {
        rule: def.name,
        paramKey,
        pattern,
        toolName: ctx.toolName,
      },
      toolName: ctx.toolName,
      toolParams: redactSensitiveValues(ctx.toolParams),
      skillName: ctx.skillName,
      sessionId: ctx.sessionId,
      agentId: ctx.agentId,
      matchedPattern: pattern,
      ruleName: def.name,
    },
  };
}

const MAX_PARAM_DEPTH = 10;

function matchAnyParam(
  params: Record<string, unknown>,
  patterns: RegExp[],
  prefix = "",
  depth = 0
): { paramKey: string; pattern: string } | null {
  if (depth > MAX_PARAM_DEPTH) return null;
  for (const [key, value] of Object.entries(params)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    if (typeof value === "string") {
      for (const rx of patterns) {
        if (rx.test(value)) {
          return { paramKey: fullKey, pattern: rx.source };
        }
      }
    } else if (value && typeof value === "object" && !Array.isArray(value)) {
      const result = matchAnyParam(
        value as Record<string, unknown>,
        patterns,
        fullKey,
        depth + 1
      );
      if (result) return result;
    } else if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        const item = value[i];
        if (typeof item === "string") {
          for (const rx of patterns) {
            if (rx.test(item)) {
              return { paramKey: `${fullKey}[${i}]`, pattern: rx.source };
            }
          }
        } else if (item && typeof item === "object" && !Array.isArray(item)) {
          const result = matchAnyParam(
            item as Record<string, unknown>,
            patterns,
            `${fullKey}[${i}]`,
            depth + 1
          );
          if (result) return result;
        }
      }
    }
  }
  return null;
}

const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
const VALID_CATEGORIES = new Set([
  "exec_danger",
  "path_violation",
  "network_suspect",
  "rate_anomaly",
  "baseline_drift",
  "prompt_injection",
  "data_exfil",
]);

function validateYamlRuleDef(
  parsed: Record<string, unknown>
): YamlRuleDefinition | null {
  const name = parsed["name"];
  const description = parsed["description"];
  const severity = parsed["severity"];
  const category = parsed["category"];
  const match = parsed["match"];

  if (
    typeof name !== "string" ||
    typeof description !== "string" ||
    typeof severity !== "string" ||
    typeof category !== "string" ||
    !match ||
    typeof match !== "object"
  ) {
    return null;
  }

  if (!VALID_SEVERITIES.has(severity) || !VALID_CATEGORIES.has(category)) {
    return null;
  }

  // Validate match structure to prevent runtime crashes from malformed input
  const matchObj = match as Record<string, unknown>;
  const validatedMatch: YamlRuleDefinition["match"] = {};

  if (typeof matchObj["toolName"] === "string") {
    validatedMatch.toolName = matchObj["toolName"];
  }

  if (matchObj["params"] && typeof matchObj["params"] === "object" && !Array.isArray(matchObj["params"])) {
    const params: Record<string, string[]> = {};
    for (const [k, v] of Object.entries(matchObj["params"] as Record<string, unknown>)) {
      if (Array.isArray(v)) {
        params[k] = v.filter((item): item is string => typeof item === "string");
      }
    }
    if (Object.keys(params).length > 0) validatedMatch.params = params;
  }

  if (Array.isArray(matchObj["any_param"])) {
    validatedMatch.any_param = (matchObj["any_param"] as unknown[]).filter(
      (item): item is string => typeof item === "string"
    );
  }

  return {
    name,
    description,
    severity: severity as Severity,
    category: category as EventCategory,
    shouldBlock: parsed["shouldBlock"] === true,
    match: validatedMatch,
  };
}
