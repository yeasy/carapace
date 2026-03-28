/**
 * NetworkGuard — 可疑网络访问检测
 *
 * 检测对数据外泄常用服务、匿名网络、
 * 裸 IP 地址、挖矿池等的网络访问。
 */

import { SEVERITY_RANK } from "../types.js";
import type { SecurityRule, RuleContext, RuleResult, Severity } from "../types.js";
import { isRedosSafe } from "../utils/regex.js";

interface DomainRule {
  pattern: RegExp;
  severity: Severity;
  title: string;
  description: string;
}

const SUSPICIOUS_DOMAINS: DomainRule[] = [
  // 粘贴/剪贴板服务（常用于数据外泄）
  {
    pattern: /\b(pastebin\.com|paste\.ee|hastebin\.com|dpaste\.org|ghostbin\.\w+)\b/i,
    severity: "high",
    title: "数据发送到粘贴服务",
    description: "向粘贴/剪贴板服务发送数据——常用于数据外泄。",
  },
  {
    pattern: /\b(transfer\.sh|file\.io|0x0\.st|tmpfiles\.org|gofile\.io)\b/i,
    severity: "high",
    title: "数据发送到文件共享服务",
    description: "向匿名文件共享服务上传数据。",
  },

  // Webhook/请求捕获服务
  {
    pattern: /\b(webhook\.site|requestbin\.com|hookbin\.com|pipedream\.net|ngrok\.\w+)\b/i,
    severity: "high",
    title: "数据发送到请求捕获服务",
    description: "向 webhook/请求捕获服务发送数据——潜在外泄端点。",
  },

  // Tor / 匿名化
  {
    pattern: /\.onion\b/i,
    severity: "critical",
    title: "Tor 隐藏服务访问",
    description: "尝试访问 Tor .onion 地址。",
  },

  // 裸 IP 地址（可能是 C2 通信）
  {
    pattern: /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?/i,
    severity: "medium",
    title: "直接 IP 地址连接",
    description: "连接到裸 IP 地址而非域名——可能是 C2 通信。",
  },

  // 加密货币挖矿池
  {
    pattern: /\b(mining-?pool|crypto-?pool|stratum\+tcp|xmrig|hashrate\.\w+|minergate)/i,
    severity: "high",
    title: "加密货币挖矿端点",
    description: "连接到疑似加密货币挖矿池。",
  },
];

// ── URL 提取 ──

function extractUrls(params: Record<string, unknown>): string[] {
  const urls: string[] = [];
  const keys = ["url", "uri", "href", "endpoint", "target", "address", "host", "domain"];
  for (const key of keys) {
    const val = params[key];
    if (typeof val === "string" && val.length > 0) urls.push(val);
  }
  // 从 command 参数中提取 URL
  if (typeof params.command === "string") {
    const matches = params.command.match(/https?:\/\/[^\s"']+/gi);
    if (matches) urls.push(...matches);
  }
  return urls;
}

// ── 规则实现 ──

export function createNetworkGuardRule(blockedDomains?: string[]): SecurityRule {
  const userRules: DomainRule[] = [];
  for (const d of blockedDomains ?? []) {
    try {
      // Use word boundary to prevent substring matches (e.g., "evil.com" should not match "notevil.com")
      const escaped = d.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const patternStr = `(?:^|[/.]|\\b)${escaped}(?:[:/]|$)`;
      if (!isRedosSafe(patternStr)) {
        process.stderr.write(`[carapace/network-guard] 忽略不安全的 blockedDomain 正则: "${d}"\n`);
        continue;
      }
      userRules.push({
        pattern: new RegExp(patternStr, "i"),
        severity: "high" as Severity,
        title: `访问被阻断域名: ${d}`,
        description: `访问用户阻断域名: ${d}`,
      });
    } catch (err) {
      // 跳过无效输入，避免运行时崩溃；输出警告帮助用户排查配置问题
      process.stderr.write(`[carapace/network-guard] 忽略无效的 blockedDomain: "${d}" — ${err instanceof Error ? err.message : String(err)}\n`);
    }
  }

  const allRules = [...SUSPICIOUS_DOMAINS, ...userRules];

  return {
    name: "network-guard",
    description: "检测可疑网络访问模式",

    check(ctx: RuleContext): RuleResult {
      const urls = extractUrls(ctx.toolParams);
      if (urls.length === 0) return { triggered: false };

      let bestMatch: { rule: DomainRule; url: string } | null = null;

      for (const url of urls) {
        for (const rule of allRules) {
          if (rule.pattern.test(url)) {
            if (
              !bestMatch ||
              SEVERITY_RANK[rule.severity] > SEVERITY_RANK[bestMatch.rule.severity]
            ) {
              bestMatch = { rule, url };
            }
            if (rule.severity === "critical") break;
          }
        }
        if (bestMatch?.rule.severity === "critical") break;
      }

      if (!bestMatch) return { triggered: false };

      const { rule, url } = bestMatch;
      return {
        triggered: true,
        shouldBlock: rule.severity === "critical",
        event: {
          category: "network_suspect",
          severity: rule.severity,
          title: rule.title,
          description: rule.description,
          details: { url, matchedPattern: rule.pattern.source },
          toolName: ctx.toolName,
          toolParams: ctx.toolParams,
          skillName: ctx.skillName,
          sessionId: ctx.sessionId,
          agentId: ctx.agentId,
          matchedPattern: rule.pattern.source,
        },
      };
    },
  };
}
