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
  { pattern: /[/\\]\.env(\.\w+)?\b/i, severity: "high", title: ".env 文件访问", category: "credentials" },
  { pattern: /[/\\]\.netrc\b/i, severity: "high", title: ".netrc 凭证访问", category: "credentials" },
  { pattern: /[/\\]\.npmrc\b/i, severity: "medium", title: ".npmrc 访问（可能含 token）", category: "credentials" },

  // Database credentials
  { pattern: /[/\\]\.pgpass\b/i, severity: "high", title: "PostgreSQL 密码文件访问", category: "credentials" },
  { pattern: /[/\\]\.my\.cnf\b/i, severity: "high", title: "MySQL 配置文件访问", category: "credentials" },

  // Cloud / DevOps tokens
  { pattern: /[/\\]\.vault-token\b/i, severity: "high", title: "HashiCorp Vault Token 访问", category: "credentials" },
  { pattern: /[/\\]\.terraform\.d[/\\]credentials\.tfrc\.json/i, severity: "high", title: "Terraform Cloud Token 访问", category: "credentials" },
  { pattern: /[/\\]\.config[/\\]gh[/\\]hosts\.yml/i, severity: "high", title: "GitHub CLI Token 访问", category: "credentials" },
  { pattern: /[/\\]\.consul[/\\]|[/\\]\.nomad[/\\]/i, severity: "high", title: "HashiCorp Consul/Nomad Token 访问", category: "credentials" },

  // Package registry credentials
  { pattern: /[/\\]\.pypirc\b/i, severity: "high", title: "PyPI 凭证访问", category: "credentials" },
  { pattern: /[/\\]\.gem[/\\]credentials\b/i, severity: "high", title: "RubyGems 凭证访问", category: "credentials" },

  // Java ecosystem credentials
  { pattern: /[/\\]\.gradle[/\\]gradle\.properties\b/i, severity: "high", title: "Gradle 凭证访问", category: "credentials" },
  { pattern: /[/\\]\.m2[/\\]settings\.xml\b/i, severity: "high", title: "Maven 仓库凭证访问", category: "credentials" },

  // GPG
  { pattern: /[/\\]\.gnupg[/\\]/i, severity: "high", title: "GPG 密钥环访问", category: "credentials" },

  // Kubernetes service account token
  { pattern: /[/\\]var[/\\]run[/\\]secrets[/\\]kubernetes\.io[/\\]/i, severity: "critical", title: "Kubernetes ServiceAccount Token 访问", category: "credentials" },

  // Rust/Cargo registry credentials
  { pattern: /[/\\]\.cargo[/\\]credentials/i, severity: "high", title: "Cargo 仓库凭证访问", category: "credentials" },

  // 浏览器数据
  { pattern: /[/\\](Chrome|Chromium|Google Chrome)[/\\].*\b(Login Data|Cookies|History|Web Data)\b/i, severity: "critical", title: "Chrome 浏览器数据访问", category: "browser" },
  { pattern: /[/\\](Firefox|Mozilla)[/\\].*\b(logins\.json|cookies\.sqlite|key[34]\.db)\b/i, severity: "critical", title: "Firefox 浏览器数据访问", category: "browser" },
  { pattern: /[/\\]Safari[/\\].*\b(Cookies\.binarycookies|History\.db)\b/i, severity: "critical", title: "Safari 浏览器数据访问", category: "browser" },

  // Linux procfs (environment variables, memory, command line, root filesystem traversal)
  { pattern: /[/\\]proc[/\\](?:self|\d+)[/\\](environ|mem|cmdline)/i, severity: "critical", title: "Linux /proc 敏感文件访问", category: "system" },
  { pattern: /[/\\]proc[/\\](?:self|\d+)[/\\]root[/\\]/i, severity: "critical", title: "Linux /proc/root 文件系统遍历", category: "system" },
  { pattern: /[/\\]proc[/\\](?:self|\d+)[/\\](fd|maps|smaps|status|stat|io|net)\b/i, severity: "high", title: "Linux /proc 信息泄露", category: "system" },

  // 系统认证
  { pattern: /[/\\]etc[/\\](passwd|shadow|sudoers)/i, severity: "high", title: "系统认证文件访问", category: "system" },

  // macOS 安全偏好
  { pattern: /[/\\]Library[/\\]Preferences[/\\]com\.apple\.security/i, severity: "high", title: "macOS 安全偏好访问", category: "system" },

  // 加密钱包
  { pattern: /[/\\]\.bitcoin[/\\]wallet\.dat/i, severity: "critical", title: "Bitcoin 钱包访问", category: "crypto_wallet" },
  { pattern: /[/\\]\.ethereum[/\\]keystore[/\\]/i, severity: "critical", title: "Ethereum 密钥库访问", category: "crypto_wallet" },

  // Kubernetes / Docker
  { pattern: /[/\\]\.kube[/\\]config/i, severity: "high", title: "Kubernetes 配置访问", category: "credentials" },
  { pattern: /[/\\]\.docker[/\\]config\.json/i, severity: "high", title: "Docker 配置访问", category: "credentials" },
  { pattern: /[/\\]run[/\\]secrets[/\\]/i, severity: "critical", title: "Docker Swarm 密钥访问", category: "credentials" },

  // SSL 私钥
  { pattern: /[/\\]etc[/\\]ssl[/\\]private[/\\]/i, severity: "critical", title: "SSL 私钥目录访问", category: "credentials" },

  // FTP/SCP 客户端凭证
  { pattern: /[/\\]\.?config[/\\]filezilla[/\\]/i, severity: "high", title: "FileZilla 保存密码访问", category: "credentials" },
  { pattern: /[/\\]WinSCP\.ini\b/i, severity: "high", title: "WinSCP 会话数据访问", category: "credentials" },

  // macOS Keychain
  { pattern: /[/\\]Keychains[/\\].*\.(keychain-db|keychain)/i, severity: "critical", title: "macOS 钥匙串访问", category: "credentials" },

  // GNOME Keyring
  { pattern: /[/\\]\.local[/\\]share[/\\]keyrings[/\\]/i, severity: "critical", title: "GNOME 密钥环访问", category: "credentials" },

  // KeePass 密码数据库
  { pattern: /[/\\][^/\\]*\.kdbx?\b/i, severity: "critical", title: "KeePass 密码数据库访问", category: "credentials" },

  // Windows 凭证
  { pattern: /[/\\]Windows[/\\]System32[/\\]config[/\\](SAM|SECURITY|SYSTEM)/i, severity: "critical", title: "Windows 凭证存储访问", category: "credentials" },
];

// ── 安全正则匹配（防止 ReDoS） ──

function safeRegexTest(regex: RegExp, input: string): boolean {
  // 对于超长输入，使用重叠滑动窗口覆盖整个字符串（防止中段 bypass）
  if (input.length > 4096) {
    try {
      const chunkSize = 4096;
      const overlap = 256;
      const step = chunkSize - overlap;
      for (let i = 0; i < input.length; i += step) {
        if (regex.test(input.slice(i, i + chunkSize))) return true;
      }
      return false;
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

const MAX_PATH_WALK_DEPTH = 10;
const MAX_PATHS = 100;

function extractPaths(params: Record<string, unknown>): string[] {
  const paths: string[] = [];

  function addPath(val: string): void {
    if (paths.length >= MAX_PATHS) return;
    // Apply Unicode NFKC normalization to prevent bypass via fullwidth characters
    // (e.g., fullwidth solidus U+FF0F normalizes to /, consistent with exec-guard)
    const normalized = val.normalize("NFKC");
    // Strip null bytes (used to truncate paths and bypass checks) before normalization
    const cleaned = normalized.includes("\0") ? normalized.replace(/\0/g, "") : normalized;
    // Iteratively decode URL-encoded paths to prevent double/triple encoding bypass
    // (e.g., %252F.ssh%252Fid_rsa → %2F.ssh%2Fid_rsa → /.ssh/id_rsa)
    let decoded = cleaned;
    for (let i = 0; i < 5; i++) {
      let next: string;
      try {
        next = decodeURIComponent(decoded);
      } catch {
        // Malformed percent-encoding: decode valid sequences, skip invalid ones
        next = decoded.replace(/%[0-9A-Fa-f]{2}/g, (m) => {
          try { return decodeURIComponent(m); } catch { return m; }
        });
      }
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
