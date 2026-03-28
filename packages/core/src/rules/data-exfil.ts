/**
 * DataExfilGuard — 数据外泄模式检测
 *
 * 检测工具调用中可能的数据外泄行为：
 * - 读取凭证后发起网络请求
 * - 大量数据通过外部上传服务传输
 * - 环境变量/密钥出现在外发请求的 URL 或 body 中
 * - 敏感数据编码后外发（base64 编码凭证）
 */

import { SEVERITY_RANK } from "../types.js";
import type { SecurityRule, RuleContext, RuleResult, Severity } from "../types.js";

interface ExfilPattern {
  pattern: RegExp;
  severity: Severity;
  title: string;
  category: string;
}

// ── 检测 URL/body 中嵌入的敏感数据特征 ──

const EXFIL_PATTERNS: ExfilPattern[] = [
  // API key / token 泄漏到请求参数
  { pattern: /(?:api[_-]?key|token|secret|password|passwd|credential|auth)\s*[=:]\s*\S{8,}/i, severity: "critical", title: "凭证出现在外发请求中", category: "credential_leak" },
  { pattern: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/i, severity: "critical", title: "AWS Access Key 出现在请求中", category: "credential_leak" },
  { pattern: /(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}/i, severity: "critical", title: "GitHub Token 出现在请求中", category: "credential_leak" },
  { pattern: /sk-[a-zA-Z0-9]{32,}/i, severity: "critical", title: "OpenAI/Stripe API Key 出现在请求中", category: "credential_leak" },
  { pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/i, severity: "critical", title: "私钥出现在请求中", category: "credential_leak" },

  // 大量 base64 编码数据外发（可能是文件/凭证编码后传输）
  { pattern: /[A-Za-z0-9+/]{200,2000}={0,2}/i, severity: "medium", title: "大块 Base64 数据外发", category: "encoded_exfil" },

  // 将文件内容通过 curl/wget 发送到外部
  { pattern: /curl\s+.*-[dX]\s+.*@\//i, severity: "high", title: "通过 curl 上传本地文件", category: "file_upload" },
  { pattern: /curl\s+.*--data-binary\s+@/i, severity: "high", title: "通过 curl 二进制上传文件", category: "file_upload" },
  { pattern: /curl\s+.*--upload-file\s+/i, severity: "high", title: "通过 curl 上传文件", category: "file_upload" },

  // 将环境变量发送到外部
  { pattern: /\$\{?\w*(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\w*\}?.*https?:\/\//i, severity: "critical", title: "环境变量凭证与 URL 组合外发", category: "env_leak" },
  { pattern: /https?:\/\/.*\$\{?\w*(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\w*\}?/i, severity: "critical", title: "凭证嵌入 URL 参数", category: "env_leak" },

  // 管道组合：读取敏感文件并发送
  { pattern: /cat\s+.*\.(pem|key|env|credentials|secret).*\|\s*(curl|wget|nc|ncat)/i, severity: "critical", title: "读取敏感文件并通过网络发送", category: "pipe_exfil" },
  { pattern: /(curl|wget|nc)\s+.*<\s*.*\.(pem|key|env|credentials|secret)/i, severity: "critical", title: "将敏感文件重定向到网络工具", category: "pipe_exfil" },
];

// ── 外泄目标域名（高风险文件共享/传输服务） ──

const EXFIL_DESTINATIONS: RegExp[] = [
  /transfer\.sh/i,
  /file\.io/i,
  /0x0\.st/i,
  /paste\.ee/i,
  /hastebin/i,
  /requestbin/i,
  /webhook\.site/i,
  /hookbin/i,
  /ngrok\.io/i,
  /burpcollaborator/i,
  /interact\.sh/i,
  /pipedream/i,
];

// ── 从工具参数提取所有字符串 ──

const MAX_WALK_DEPTH = 10;
const MAX_STRING_LEN = 8192;
const MAX_TOTAL_LENGTH = 100_000;
const MAX_STRING_COUNT = 1000;

function extractAllStrings(params: Record<string, unknown>): string[] {
  const strings: string[] = [];
  let totalLength = 0;

  function walk(val: unknown, depth: number): void {
    if (depth > MAX_WALK_DEPTH || strings.length >= MAX_STRING_COUNT || totalLength >= MAX_TOTAL_LENGTH) return;
    if (typeof val === "string" && val.length > 0) {
      const s = val.length > MAX_STRING_LEN ? val.slice(0, MAX_STRING_LEN) : val;
      strings.push(s);
      totalLength += s.length;
    } else if (Array.isArray(val)) {
      for (const item of val) walk(item, depth + 1);
    } else if (val && typeof val === "object") {
      for (const v of Object.values(val as Record<string, unknown>)) walk(v, depth + 1);
    }
  }

  walk(params, 0);
  return strings;
}

// ── 规则实现 ──

export function createDataExfilRule(): SecurityRule {
  return {
    name: "data-exfil",
    description: "检测工具调用中的数据外泄模式",

    check(ctx: RuleContext): RuleResult {
      const strings = extractAllStrings(ctx.toolParams);
      if (strings.length === 0) return { triggered: false };

      const combined = strings.join("\n");

      // Find the highest-severity exfil pattern match
      let bestMatch: { ep: ExfilPattern; snippet: string } | null = null;

      for (const ep of EXFIL_PATTERNS) {
        if (ep.pattern.test(combined)) {
          if (
            !bestMatch ||
            SEVERITY_RANK[ep.severity] > SEVERITY_RANK[bestMatch.ep.severity]
          ) {
            const match = combined.match(ep.pattern);
            bestMatch = { ep, snippet: match ? match[0].slice(0, 100) : "" };
          }
          if (ep.severity === "critical") break;
        }
      }

      // 检查是否向高风险外泄目标发送数据 (always critical)
      for (const dest of EXFIL_DESTINATIONS) {
        if (dest.test(combined)) {
          const hasSendAction = /(?:POST|PUT|PATCH|upload|send|--data|--form|-d\s|-F\s)/i.test(combined);
          if (hasSendAction) {
            const match = combined.match(dest);
            // Exfil destinations are always critical, override pattern match
            return {
              triggered: true,
              shouldBlock: true,
              event: {
                category: "data_exfil",
                severity: "critical",
                title: "向已知外泄目标发送数据",
                description: `工具 "${ctx.toolName}" 正在向已知文件共享/外泄服务发送数据`,
                details: {
                  exfilCategory: "exfil_destination",
                  destination: match ? match[0] : "unknown",
                },
                toolName: ctx.toolName,
                toolParams: ctx.toolParams,
                skillName: ctx.skillName,
                sessionId: ctx.sessionId,
                agentId: ctx.agentId,
                matchedPattern: dest.source,
              },
            };
          }
        }
      }

      if (!bestMatch) return { triggered: false };

      const { ep, snippet } = bestMatch;
      return {
        triggered: true,
        shouldBlock: ep.severity === "critical",
        event: {
          category: "data_exfil",
          severity: ep.severity,
          title: ep.title,
          description: `工具 "${ctx.toolName}" 中检测到数据外泄模式（${ep.category}类）`,
          details: {
            exfilCategory: ep.category,
            matchedPattern: ep.pattern.source,
            snippet,
          },
          toolName: ctx.toolName,
          toolParams: ctx.toolParams,
          skillName: ctx.skillName,
          sessionId: ctx.sessionId,
          agentId: ctx.agentId,
          matchedPattern: ep.pattern.source,
        },
      };
    },
  };
}
