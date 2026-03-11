/**
 * PathGuard — 敏感文件路径访问检测
 *
 * 检测工具调用中对敏感文件路径的访问：
 * SSH 密钥、云凭证、浏览器数据、加密钱包、系统认证文件。
 * 跨平台：覆盖 Windows、macOS、Linux 路径。
 */

import type { SecurityRule, RuleContext, RuleResult, Severity } from "../types.js";

interface SensitivePath {
  pattern: RegExp;
  severity: Severity;
  title: string;
  category: string;
}

const SENSITIVE_PATHS: SensitivePath[] = [
  // SSH
  { pattern: /[/\\]\.ssh[/\\](id_rsa|id_ed25519|id_ecdsa|id_dsa|known_hosts|authorized_keys|config)/i, severity: "critical", title: "SSH 密钥/配置访问", category: "credentials" },
  { pattern: /[/\\]\.ssh[/\\]/i, severity: "high", title: "SSH 目录访问", category: "credentials" },

  // 云凭证
  { pattern: /[/\\]\.aws[/\\](credentials|config)/i, severity: "critical", title: "AWS 凭证访问", category: "credentials" },
  { pattern: /[/\\]\.azure[/\\]/i, severity: "high", title: "Azure 配置访问", category: "credentials" },
  { pattern: /[/\\]\.config[/\\]gcloud[/\\]/i, severity: "high", title: "GCloud 配置访问", category: "credentials" },

  // API 密钥和 token
  { pattern: /[/\\]\.env(\.(local|production|development|staging))?\b/i, severity: "high", title: ".env 文件访问", category: "credentials" },
  { pattern: /[/\\]\.netrc\b/i, severity: "high", title: ".netrc 凭证访问", category: "credentials" },
  { pattern: /[/\\]\.npmrc\b/i, severity: "medium", title: ".npmrc 访问（可能含 token）", category: "credentials" },

  // GPG
  { pattern: /[/\\]\.gnupg[/\\]/i, severity: "high", title: "GPG 密钥环访问", category: "credentials" },

  // 浏览器数据
  { pattern: /[/\\](Chrome|Chromium|Google Chrome)[/\\].*\b(Login Data|Cookies|History|Web Data)\b/i, severity: "critical", title: "Chrome 浏览器数据访问", category: "browser" },
  { pattern: /[/\\](Firefox|Mozilla)[/\\].*\b(logins\.json|cookies\.sqlite|key[34]\.db)\b/i, severity: "critical", title: "Firefox 浏览器数据访问", category: "browser" },
  { pattern: /[/\\]Safari[/\\].*\b(Cookies\.binarycookies|History\.db)\b/i, severity: "critical", title: "Safari 浏览器数据访问", category: "browser" },

  // 系统认证
  { pattern: /[/\\]etc[/\\](passwd|shadow|sudoers)/i, severity: "high", title: "系统认证文件访问", category: "system" },

  // 加密钱包
  { pattern: /[/\\]\.bitcoin[/\\]wallet\.dat/i, severity: "critical", title: "Bitcoin 钱包访问", category: "crypto_wallet" },
  { pattern: /[/\\]\.ethereum[/\\]keystore[/\\]/i, severity: "critical", title: "Ethereum 密钥库访问", category: "crypto_wallet" },

  // Kubernetes / Docker
  { pattern: /[/\\]\.kube[/\\]config/i, severity: "high", title: "Kubernetes 配置访问", category: "credentials" },
  { pattern: /[/\\]\.docker[/\\]config\.json/i, severity: "high", title: "Docker 配置访问", category: "credentials" },

  // macOS Keychain
  { pattern: /[/\\]Keychains[/\\].*\.(keychain-db|keychain)/i, severity: "critical", title: "macOS 钥匙串访问", category: "credentials" },

  // Windows 凭证
  { pattern: /[/\\]Windows[/\\]System32[/\\]config[/\\](SAM|SECURITY|SYSTEM)/i, severity: "critical", title: "Windows 凭证存储访问", category: "credentials" },
];

// ── 路径提取 ──

function extractPaths(params: Record<string, unknown>): string[] {
  const paths: string[] = [];
  const keys = [
    "path", "file", "filepath", "file_path", "filename",
    "src", "dest", "source", "destination", "target",
    "input", "output", "command",
  ];
  for (const key of keys) {
    const val = params[key];
    if (typeof val === "string" && val.length > 0) paths.push(val);
  }
  return paths;
}

// ── 规则实现 ──

export function createPathGuardRule(additionalPatterns?: string[]): SecurityRule {
  const userPatterns: SensitivePath[] = [];
  for (const p of additionalPatterns ?? []) {
    try {
      userPatterns.push({
        pattern: new RegExp(p, "i"),
        severity: "high" as Severity,
        title: `自定义敏感路径匹配: ${p}`,
        category: "custom",
      });
    } catch {
      // 跳过无效正则，避免运行时崩溃
    }
  }

  const allPatterns = [...SENSITIVE_PATHS, ...userPatterns];

  return {
    name: "path-guard",
    description: "检测对敏感文件路径的访问",

    check(ctx: RuleContext): RuleResult {
      const paths = extractPaths(ctx.toolParams);
      if (paths.length === 0) return { triggered: false };

      for (const filePath of paths) {
        for (const sp of allPatterns) {
          if (sp.pattern.test(filePath)) {
            return {
              triggered: true,
              shouldBlock: sp.severity === "critical",
              event: {
                category: "path_violation",
                severity: sp.severity,
                title: sp.title,
                description: `工具 "${ctx.toolName}" 尝试访问敏感路径（${sp.category}类）`,
                details: {
                  path: filePath,
                  matchedPattern: sp.pattern.source,
                  pathCategory: sp.category,
                },
                toolName: ctx.toolName,
                toolParams: ctx.toolParams,
                skillName: ctx.skillName,
                sessionId: ctx.sessionId,
                agentId: ctx.agentId,
                matchedPattern: sp.pattern.source,
              },
            };
          }
        }
      }
      return { triggered: false };
    },
  };
}
