/**
 * PathGuard — 敏感文件路径访问检测
 *
 * 检测工具调用中对敏感文件路径的访问：
 * SSH 密钥、云凭证、浏览器数据、加密钱包、系统认证文件。
 * 跨平台：覆盖 Windows、macOS、Linux 路径。
 */

import * as nodePath from "node:path";
import { SEVERITY_RANK } from "../types.js";
import type { SecurityRule, RuleContext, RuleResult, Severity } from "../types.js";
import { isRedosSafe } from "../utils/regex.js";
import { redactSensitiveValues } from "../utils/redact.js";

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

// ── 安全正则匹配（防止 ReDoS） ──

function safeRegexTest(regex: RegExp, input: string): boolean {
  // 对于超长输入，检查头尾两段以避免 ReDoS 同时防止尾部 bypass
  if (input.length > 4096) {
    try {
      return regex.test(input.slice(0, 4096)) || regex.test(input.slice(-2048));
    } catch {
      return false;
    }
  }
  try {
    return regex.test(input);
  } catch {
    return false;
  }
}

// ── 路径提取 ──

const PATH_KEYS = new Set([
  "path", "file", "filepath", "file_path", "filename",
  "src", "dest", "source", "destination", "target",
  "input", "output", "command",
  "dir", "directory", "folder", "location",
  "read_file", "write_file", "from", "to",
  "cwd", "working_directory", "base_path", "root",
  "content", "url", "uri",
]);

const MAX_PATH_WALK_DEPTH = 5;
const MAX_PATHS = 100;

function extractPaths(params: Record<string, unknown>): string[] {
  const paths: string[] = [];

  function addPath(val: string): void {
    if (paths.length >= MAX_PATHS) return;
    // Strip null bytes (used to truncate paths and bypass checks) before normalization
    const cleaned = val.includes("\0") ? val.replace(/\0/g, "") : val;
    // Iteratively decode URL-encoded paths to prevent double/triple encoding bypass
    // (e.g., %252F.ssh%252Fid_rsa → %2F.ssh%2Fid_rsa → /.ssh/id_rsa)
    let decoded = cleaned;
    for (let i = 0; i < 5; i++) {
      let next: string;
      try { next = decodeURIComponent(decoded); } catch { break; }
      if (next === decoded) break;
      decoded = next;
    }
    try {
      paths.push(nodePath.normalize(decoded));
    } catch {
      paths.push(decoded);
    }
  }

  function walk(obj: unknown, depth: number): void {
    if (depth > MAX_PATH_WALK_DEPTH || paths.length >= MAX_PATHS) return;
    if (typeof obj === "string" && obj.length > 0) {
      addPath(obj);
    } else if (Array.isArray(obj)) {
      for (const item of obj) walk(item, depth + 1);
    } else if (obj && typeof obj === "object") {
      for (const [key, val] of Object.entries(obj as Record<string, unknown>)) {
        if (typeof val === "string" && val.length > 0) {
          if (PATH_KEYS.has(key.toLowerCase())) {
            // Known path-like key — always inspect
            addPath(val);
          } else if (val.includes("/") || val.includes("\\")) {
            // Unknown key but value looks like a file path — inspect it
            addPath(val);
          }
        } else if (val && typeof val === "object") {
          walk(val, depth + 1);
        }
      }
    }
  }

  walk(params, 0);
  return paths;
}

// ── 规则实现 ──

export function createPathGuardRule(additionalPatterns?: string[]): SecurityRule {
  const userPatterns: SensitivePath[] = [];
  for (const p of additionalPatterns ?? []) {
    try {
      if (!isRedosSafe(p)) {
        process.stderr.write(`[carapace/path-guard] 拒绝可能导致 ReDoS 的 sensitivePathPattern: "${p}"\n`);
        continue;
      }
      userPatterns.push({
        pattern: new RegExp(p, "i"),
        severity: "high" as Severity,
        title: `自定义敏感路径匹配: ${p}`,
        category: "custom",
      });
    } catch (err) {
      // 跳过无效正则，避免运行时崩溃；输出警告帮助用户排查配置问题
      process.stderr.write(`[carapace/path-guard] 忽略无效的 sensitivePathPattern: "${p}" — ${err instanceof Error ? err.message : String(err)}\n`);
    }
  }

  const allPatterns = [...SENSITIVE_PATHS, ...userPatterns];

  return {
    name: "path-guard",
    description: "检测对敏感文件路径的访问",

    check(ctx: RuleContext): RuleResult {
      const paths = extractPaths(ctx.toolParams);
      if (paths.length === 0) return { triggered: false };

      let bestMatch: { sp: SensitivePath; filePath: string } | null = null;

      for (const filePath of paths) {
        for (const sp of allPatterns) {
          if (safeRegexTest(sp.pattern, filePath)) {
            if (
              !bestMatch ||
              SEVERITY_RANK[sp.severity] > SEVERITY_RANK[bestMatch.sp.severity]
            ) {
              bestMatch = { sp, filePath };
            }
            // Short-circuit: can't get higher than critical
            if (sp.severity === "critical") break;
          }
        }
        if (bestMatch?.sp.severity === "critical") break;
      }

      if (!bestMatch) return { triggered: false };

      const { sp, filePath } = bestMatch;
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
          toolParams: redactSensitiveValues(ctx.toolParams),
          skillName: ctx.skillName,
          sessionId: ctx.sessionId,
          agentId: ctx.agentId,
          matchedPattern: sp.pattern.source,
        },
      };
    },
  };
}
