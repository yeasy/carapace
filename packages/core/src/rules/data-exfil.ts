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
import { redactSensitiveValues } from "../utils/redact.js";

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
  { pattern: /(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/, severity: "critical", title: "AWS Access Key 出现在请求中", category: "credential_leak" },
  { pattern: /(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{36,}/i, severity: "critical", title: "GitHub Token 出现在请求中", category: "credential_leak" },
  { pattern: /\bsk-[a-zA-Z0-9_-]{32,}/i, severity: "critical", title: "OpenAI API Key 出现在请求中", category: "credential_leak" },
  { pattern: /\bsk_(?:live|test)_[a-zA-Z0-9]{20,}/i, severity: "critical", title: "Stripe API Key 出现在请求中", category: "credential_leak" },
  { pattern: /sk-ant-[a-zA-Z0-9_-]{20,}/i, severity: "critical", title: "Anthropic API Key 出现在请求中", category: "credential_leak" },
  { pattern: /AIzaSy[a-zA-Z0-9_-]{33}/, severity: "critical", title: "Google API Key 出现在请求中", category: "credential_leak" },
  { pattern: /xox[bpsar]-[0-9a-zA-Z-]{20,}/, severity: "critical", title: "Slack Token 出现在请求中", category: "credential_leak" },
  { pattern: /-----BEGIN\s+(RSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/i, severity: "critical", title: "私钥出现在请求中", category: "credential_leak" },
  { pattern: /\bglpat-[A-Za-z0-9_-]{20,}/, severity: "critical", title: "GitLab Personal Access Token 出现在请求中", category: "credential_leak" },
  { pattern: /\bnpm_[A-Za-z0-9]{36,}/, severity: "critical", title: "NPM Token 出现在请求中", category: "credential_leak" },
  { pattern: /\bpypi-[A-Za-z0-9_-]{16,}/, severity: "critical", title: "PyPI Token 出现在请求中", category: "credential_leak" },
  { pattern: /\bhf_[A-Za-z0-9]{20,}/, severity: "critical", title: "HuggingFace Token 出现在请求中", category: "credential_leak" },
  { pattern: /\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}/, severity: "critical", title: "SendGrid API Key 出现在请求中", category: "credential_leak" },
  { pattern: /\bdop_v1_[a-f0-9]{64}/, severity: "critical", title: "DigitalOcean Token 出现在请求中", category: "credential_leak" },
  { pattern: /\bhvs\.[A-Za-z0-9_-]{20,}/, severity: "critical", title: "HashiCorp Vault Token 出现在请求中", category: "credential_leak" },

  // Base64 encoded credentials (~40+ chars covers typical API keys/tokens)
  // Includes base64url charset (-_ instead of +/) used by JWTs and URL-safe tokens
  { pattern: /(?<=\s|^|["'`])[A-Za-z0-9+/\-_]{40,16000}={0,2}(?=\s|$|["'`])/, severity: "medium", title: "Base64 编码数据外发", category: "encoded_exfil" },

  // 将文件内容通过 curl/wget 发送到外部
  { pattern: /curl\s+.*-[dX]\s+.*@\.?\//i, severity: "high", title: "通过 curl 上传本地文件", category: "file_upload" },
  { pattern: /curl\s+.*--data-binary\s+@/i, severity: "high", title: "通过 curl 二进制上传文件", category: "file_upload" },
  { pattern: /curl\s+.*--upload-file\s+/i, severity: "high", title: "通过 curl 上传文件", category: "file_upload" },
  { pattern: /curl\s+.*-F\s+.*@\.?\//i, severity: "high", title: "通过 curl multipart 上传本地文件", category: "file_upload" },
  { pattern: /curl\s+.*-T\s+/i, severity: "high", title: "通过 curl -T 上传文件", category: "file_upload" },
  { pattern: /\bftp\s+.*-[snp]/i, severity: "high", title: "通过 FTP 传输数据", category: "file_upload" },

  // 将环境变量发送到外部
  { pattern: /\$\{?\w*(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\w*\}?.*https?:\/\//i, severity: "critical", title: "环境变量凭证与 URL 组合外发", category: "env_leak" },
  { pattern: /https?:\/\/.*\$\{?\w*(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)\w*\}?/i, severity: "critical", title: "凭证嵌入 URL 参数", category: "env_leak" },

  // wget --post-file / --body-file 文件上传
  { pattern: /wget\s+.*--post-file[=\s]/i, severity: "high", title: "通过 wget 上传文件", category: "file_upload" },
  { pattern: /wget\s+.*--body-file[=\s]/i, severity: "high", title: "通过 wget --body-file 上传文件", category: "file_upload" },
  { pattern: /\brclone\s+(?:copy|sync|move|mount)\s/i, severity: "high", title: "通过 rclone 传输到云存储", category: "file_upload" },

  // 通过消息平台 webhook/API 外泄
  { pattern: /api\.telegram\.org\/bot[A-Za-z0-9_:-]+\/send/i, severity: "critical", title: "通过 Telegram Bot 发送数据", category: "exfil_destination" },
  { pattern: /discord(?:app)?\.com\/api\/webhooks\//i, severity: "critical", title: "通过 Discord Webhook 发送数据", category: "exfil_destination" },

  // 管道组合：读取敏感文件并发送
  { pattern: /(?:cat|head|tail|dd|strings|base64|xxd|tac|nl|less|more)\s+.*\.(pem|key|env|credentials|secret).*\|\s*(curl|wget|nc|ncat)/i, severity: "critical", title: "读取敏感文件并通过网络发送", category: "pipe_exfil" },
  { pattern: /(curl|wget|nc)\s+.*<\s*.*\.(pem|key|env|credentials|secret)/i, severity: "critical", title: "将敏感文件重定向到网络工具", category: "pipe_exfil" },
  // Redirect credential paths (not just extensions) to network tools
  { pattern: /(nc|ncat)\s+\S+\s+\d+\s*<\s*.*~?\/?\.(?:ssh|aws|config\/gcloud)\//i, severity: "critical", title: "凭证文件重定向到 netcat", category: "pipe_exfil" },
  { pattern: /(?:cat|head|tail|dd|strings|base64|xxd|tac|nl|less|more)\s+.*~?\/?\.(?:ssh|aws)\/(id_rsa|id_ed25519|credentials).*\|\s*(curl|wget|nc|ncat)/i, severity: "critical", title: "读取凭证文件并通过网络发送", category: "pipe_exfil" },

  // GPG 私钥通过网络导出
  { pattern: /gpg\s+.*--export-secret-keys.*\|\s*(curl|wget|nc|ncat)/i, severity: "critical", title: "GPG 私钥导出并通过网络发送", category: "pipe_exfil" },

  // scp 凭证文件外泄
  { pattern: /\bscp\s+.*~?\/?\.(?:ssh|aws|gnupg|config\/gcloud)\//i, severity: "critical", title: "通过 scp 外泄凭证文件", category: "pipe_exfil" },

  // tar/zip pipe to network tool exfiltration
  { pattern: /\b(tar|zip)\s+.*~?\/?\.(?:ssh|aws)\b.*\|\s*(curl|wget|nc|ncat)/i, severity: "critical", title: "通过 tar/zip 管道外泄凭证", category: "pipe_exfil" },

  // rsync credential exfiltration
  { pattern: /\brsync\s+.*~?\/?\.(?:ssh|aws|gnupg|config\/gcloud)\//i, severity: "critical", title: "通过 rsync 外泄凭证文件", category: "pipe_exfil" },

  // socat / openssl s_client data exfiltration
  { pattern: /(?:cat|head|tail|dd|strings|base64|xxd|tac|nl|less|more)\s+.*\.(pem|key|env|credentials|secret).*\|\s*(socat|openssl)/i, severity: "critical", title: "通过 socat/openssl 外泄敏感文件", category: "pipe_exfil" },
  { pattern: /(socat|openssl\s+s_client)\s+.*<\s*.*\.(pem|key|env|credentials|secret)/i, severity: "critical", title: "将敏感文件重定向到 socat/openssl", category: "pipe_exfil" },
  { pattern: /(?:cat|head|tail|dd|strings|base64|xxd|tac|nl|less|more)\s+.*~?\/?\.(?:ssh|aws)\/(id_rsa|id_ed25519|credentials).*\|\s*(socat|openssl)/i, severity: "critical", title: "通过 socat/openssl 外泄凭证文件", category: "pipe_exfil" },

  // /dev/tcp data exfiltration (non-shell redirect)
  { pattern: />\s*\/dev\/tcp\/\S+\/\d+/i, severity: "critical", title: "通过 /dev/tcp 外泄数据", category: "pipe_exfil" },

  // DNS 外泄：通过 dig/nslookup/host 将命令替换结果嵌入查询域名
  { pattern: /(?:dig|nslookup|host)\s+.*\$\(.*\).*\.\S+/i, severity: "critical", title: "DNS 查询中嵌入命令替换（DNS 外泄）", category: "dns_exfil" },
  { pattern: /(?:dig|nslookup|host)\s+.*`[^`]+`.*\.\S+/i, severity: "critical", title: "DNS 查询中嵌入命令替换（DNS 外泄）", category: "dns_exfil" },
];

// ── 外泄目标域名（高风险文件共享/传输服务） ──

const EXFIL_DESTINATIONS: RegExp[] = [
  /(?:^|[\s/.@])transfer\.sh(?:$|[\s/:?#])/i,
  /(?:^|[\s/.@])file\.io(?:$|[\s/:?#])/i,
  /(?:^|[\s/.@])0x0\.st(?:$|[\s/:?#])/i,
  /(?:^|[\s/.@])paste\.ee(?:$|[\s/:?#])/i,
  /\bhastebin\b/i,
  /\brequestbin\b/i,
  /(?:^|[\s/.@])webhook\.site(?:$|[\s/:?#])/i,
  /\bhookbin\b/i,
  /(?:^|[\s/.@])ngrok\.io(?:$|[\s/:?#])/i,
  /(?:^|[\s/.@])ngrok-free\.app(?:$|[\s/:?#])/i,
  /\bburpcollaborator\b/i,
  /(?:^|[\s/.@])interact\.sh(?:$|[\s/:?#])/i,
  /\bpipedream\.net\b/i,
  /(?:^|[\s/.@])ix\.io(?:$|[\s/:?#])/i,
  /(?:^|[\s/.@])sprunge\.us(?:$|[\s/:?#])/i,
  /(?:^|[\s/.@])termbin\.com(?:$|[\s/:?#])/i,
  /\boastify\.com\b/i,
  /(?:^|[\s/.@])api\.telegram\.org(?:$|[\s/:?#])/i,
  /(?:^|[\s/.@])discord(?:app)?\.com\/api\/webhooks(?:$|[\s/:?#])/i,
];

// ── 从工具参数提取所有字符串 ──

const MAX_WALK_DEPTH = 10;
const MAX_STRING_LEN = 8192;
const MAX_TOTAL_LENGTH = 100_000;
const MAX_STRING_COUNT = 1000;

// Strip invisible Unicode characters (consistent with exec-guard and prompt-injection)
const INVISIBLE_CHARS_RE = /[\u00AD\u115F\u1160\u180E\u200B-\u200F\u2028-\u202F\u2060-\u2069\u2800\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF9-\uFFFB]|\uDB40[\uDC01-\uDC7F]/g;

function normalizeForExfilDetection(text: string): string {
  return text.normalize("NFKC").replace(INVISIBLE_CHARS_RE, "");
}

function extractAllStrings(params: Record<string, unknown>): string[] {
  const strings: string[] = [];
  let totalLength = 0;

  function walk(val: unknown, depth: number): void {
    if (depth > MAX_WALK_DEPTH || strings.length >= MAX_STRING_COUNT || totalLength >= MAX_TOTAL_LENGTH) return;
    if (typeof val === "string" && val.length > 0) {
      let s: string;
      if (val.length > MAX_STRING_LEN) {
        // Use overlapping chunks to cover the entire string (prevent mid-string bypass)
        const chunkSize = MAX_STRING_LEN;
        const overlap = 256;
        const step = chunkSize - overlap;
        for (let i = 0; i < val.length; i += step) {
          const chunk = normalizeForExfilDetection(val.slice(i, i + chunkSize));
          strings.push(chunk);
          totalLength += chunk.length;
          if (strings.length >= MAX_STRING_COUNT || totalLength >= MAX_TOTAL_LENGTH) return;
        }
        return;
      } else {
        s = val;
      }
      s = normalizeForExfilDetection(s);
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

      // Cap combined length to prevent computational amplification from regex matching.
      // Use overlapping sliding windows to prevent mid-string bypass.
      const MAX_COMBINED_LEN = 65_536;
      const combined = strings.join("\n");
      const combinedChunks: string[] = [];
      if (combined.length > MAX_COMBINED_LEN) {
        const chunkSize = MAX_COMBINED_LEN;
        const overlap = 512;
        const step = chunkSize - overlap;
        for (let i = 0; i < combined.length; i += step) {
          combinedChunks.push(combined.slice(i, i + chunkSize));
        }
      } else {
        combinedChunks.push(combined);
      }

      // Find the highest-severity exfil pattern match (scan all chunks)
      let bestMatch: { ep: ExfilPattern; snippet: string } | null = null;

      for (const chunk of combinedChunks) {
        for (const ep of EXFIL_PATTERNS) {
          const match = ep.pattern.exec(chunk);
          if (match) {
            if (
              !bestMatch ||
              SEVERITY_RANK[ep.severity] > SEVERITY_RANK[bestMatch.ep.severity]
            ) {
              bestMatch = { ep, snippet: match[0].slice(0, 100) };
            }
            if (ep.severity === "critical") break;
          }
        }
        if (bestMatch?.ep.severity === "critical") break;
      }

      // 检查是否向高风险外泄目标发送数据 (always critical, scan all chunks)
      for (const chunk of combinedChunks) {
        for (const dest of EXFIL_DESTINATIONS) {
          const match = dest.exec(chunk);
          if (match) {
            const hasSendAction = /(?:POST|PUT|PATCH|upload|send|--data(?:-raw|-urlencode)?|--form|--upload-file|--post-file|--post-data|--body-file|--json|-d[\s@"']|-F[\s@"']|-T\s|-XPOST|-XPUT)/i.test(chunk);
            const hasCmdSubstitution = /\$\([^)]+\)|`[^`]+`|\$\{[^}]+\}/.test(chunk);
            const hasSensitiveParams = /\?\S*(?:data|secret|token|key|passwd|password|credential|file)=/i.test(chunk);
            if (hasSendAction || hasCmdSubstitution || hasSensitiveParams) {
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
                  toolParams: redactSensitiveValues(ctx.toolParams),
                  skillName: ctx.skillName,
                  sessionId: ctx.sessionId,
                  agentId: ctx.agentId,
                  matchedPattern: dest.source,
                },
              };
            }
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
          toolParams: redactSensitiveValues(ctx.toolParams),
          skillName: ctx.skillName,
          sessionId: ctx.sessionId,
          agentId: ctx.agentId,
          matchedPattern: ep.pattern.source,
        },
      };
    },
  };
}
