/**
 * NetworkGuard — 可疑网络访问检测
 *
 * 检测对数据外泄常用服务、匿名网络、
 * 裸 IP 地址、挖矿池等的网络访问。
 */

import { SEVERITY_RANK } from "../types.js";
import type { SecurityRule, RuleContext, RuleResult, Severity } from "../types.js";
import { isRedosSafe } from "../utils/regex.js";
import { redactSensitiveValues } from "../utils/redact.js";

interface DomainRule {
  pattern: RegExp;
  severity: Severity;
  title: string;
  description: string;
}

const SUSPICIOUS_DOMAINS: DomainRule[] = [
  // 粘贴/剪贴板服务（常用于数据外泄）
  {
    pattern: /\b(pastebin\.com|paste\.ee|hastebin\.com|dpaste\.org|ghostbin\.\w+|privatebin\.net|rentry\.co)\b/i,
    severity: "high",
    title: "数据发送到粘贴服务",
    description: "向粘贴/剪贴板服务发送数据——常用于数据外泄。",
  },
  {
    pattern: /\b(paste\.mozilla\.org|toptal\.com\/developers\/hastebin|cl1p\.net|controlc\.com)\b/i,
    severity: "high",
    title: "数据发送到粘贴服务",
    description: "向粘贴/剪贴板服务发送数据——常用于数据外泄。",
  },
  {
    pattern: /\b(transfer\.sh|file\.io|0x0\.st|tmpfiles\.org|gofile\.io|temp\.sh|oshi\.at|catbox\.moe|fileditch\.com|anonfiles\.com|sendspace\.com|dropmefiles\.com)\b/i,
    severity: "high",
    title: "数据发送到文件共享服务",
    description: "向匿名文件共享服务上传数据。",
  },

  // Webhook/请求捕获服务
  {
    pattern: /\b(webhook\.site|requestbin\.com|hookbin\.com|pipedream\.net|ngrok\.\w+|ngrok-free\.app|bore\.pub|localtunnel\.me|serveo\.net|localhost\.run|trycloudflare\.com|beeceptor\.com|pinggy\.io)\b/i,
    severity: "high",
    title: "数据发送到请求捕获/隧道服务",
    description: "向 webhook/请求捕获/隧道服务发送数据——潜在外泄端点。",
  },
  {
    pattern: /\b(playit\.gg|telebit\.cloud|remote\.it|portmap\.io)\b/i,
    severity: "high",
    title: "数据发送到隧道服务",
    description: "向隧道/端口转发服务发送数据——潜在外泄端点。",
  },

  // Tor / 匿名化
  {
    pattern: /\.onion\b/i,
    severity: "critical",
    title: "Tor 隐藏服务访问",
    description: "尝试访问 Tor .onion 地址。",
  },

  // 裸 IP 地址（可能是 C2 通信）— IPv4 and IPv6
  {
    pattern: /(?:https?|ftp|wss?|gopher|ldap|dict|sftp|telnet|tftp):\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?/i,
    severity: "medium",
    title: "直接 IP 地址连接",
    description: "连接到裸 IP 地址而非域名——可能是 C2 通信。",
  },
  {
    pattern: /(?:https?|ftp|wss?|gopher|ldap|dict|sftp|telnet|tftp):\/\/\[[0-9a-fA-F:]+\]/i,
    severity: "medium",
    title: "IPv6 直接地址连接",
    description: "连接到裸 IPv6 地址而非域名——可能是 C2 通信。",
  },

  // Decimal IP encoding (e.g., http://3232235777 = 192.168.1.1)
  {
    pattern: /(?:https?|ftp|wss?|gopher|ldap|dict|sftp|telnet|tftp):\/\/\d{8,10}(?:[:/]|$)/i,
    severity: "high",
    title: "十进制编码 IP 连接",
    description: "通过十进制编码 IP 地址连接——绕过域名检测的常见 C2 手法。",
  },
  // Octal IP encoding (e.g., http://0300.0250.0001.0001 or mixed http://0300.250.0001.1)
  // First octet must be a clear octal number (0 + 2-3 octal digits), remaining can be decimal
  {
    pattern: /(?:https?|ftp|wss?|gopher|ldap|dict|sftp|telnet|tftp):\/\/0[0-7]{2,3}(?:\.0?[0-7]{1,3}){3}/i,
    severity: "high",
    title: "八进制编码 IP 连接",
    description: "通过八进制编码 IP 地址连接——绕过域名检测的 C2 手法。",
  },
  // Hex IP encoding (e.g., http://0xC0.0xA8.0x01.0x01 or http://0xC0A80101)
  {
    pattern: /(?:https?|ftp|wss?|gopher|ldap|dict|sftp|telnet|tftp):\/\/0x[0-9a-fA-F]+(?:\.0x[0-9a-fA-F]+){0,3}(?:[:/]|$)/i,
    severity: "high",
    title: "十六进制编码 IP 连接",
    description: "通过十六进制编码 IP 地址连接——绕过域名检测的 C2 手法。",
  },

  // 加密货币挖矿池
  {
    pattern: /\b(mining-?pool|crypto-?pool|stratum\+tcp|xmrig|hashrate\.\w+|minergate)/i,
    severity: "high",
    title: "加密货币挖矿端点",
    description: "连接到疑似加密货币挖矿池。",
  },

  // DNS 外泄/带外交互服务
  {
    pattern: /\b(dnsbin\.zhack\.ca|ceye\.io|oob\.li|interact\.sh|oast\.\w+)\b/i,
    severity: "high",
    title: "DNS 外泄/交互服务",
    description: "连接到 DNS 外泄或带外交互测试服务。",
  },

  // 云实例元数据端点（SSRF 目标）
  {
    pattern: /169\.254\.169\.254/,
    severity: "critical",
    title: "云实例元数据访问",
    description: "访问云实例元数据服务 (169.254.169.254)——常见 SSRF 凭证窃取目标。",
  },
  {
    pattern: /metadata\.google\.internal/i,
    severity: "critical",
    title: "GCP 元数据服务访问",
    description: "访问 GCP 实例元数据服务——可获取服务账号凭证。",
  },
  {
    pattern: /metadata\.azure\.com/i,
    severity: "critical",
    title: "Azure 元数据服务访问",
    description: "访问 Azure 实例元数据服务——可获取托管身份凭证。",
  },
  {
    pattern: /metadata\.oraclecloud\.com/i,
    severity: "critical",
    title: "Oracle Cloud 元数据访问",
    description: "访问 Oracle Cloud 实例元数据服务。",
  },
  {
    pattern: /\bmetadata\.internal\b/i,
    severity: "critical",
    title: "DigitalOcean 元数据访问",
    description: "访问 DigitalOcean Droplet 元数据服务。",
  },
  {
    pattern: /\bkubernetes\.default\.svc\b/i,
    severity: "medium",
    title: "Kubernetes API 内部访问",
    description: "从 Pod 内部访问 Kubernetes API——可能获取集群权限。",
  },

  // Cloud metadata — alternative IP encodings for 169.254.169.254
  {
    pattern: /\b2852039166\b/,
    severity: "critical",
    title: "云元数据访问（十进制 IP）",
    description: "十进制编码访问云元数据端点 (169.254.169.254)。",
  },
  {
    pattern: /0xa9[.]?fe[.]?a9[.]?fe|0xa9fea9fe/i,
    severity: "critical",
    title: "云元数据访问（十六进制 IP）",
    description: "十六进制编码访问云元数据端点 (169.254.169.254)。",
  },
  {
    pattern: /0251[.]0376[.]0251[.]0376/,
    severity: "critical",
    title: "云元数据访问（八进制 IP）",
    description: "八进制编码访问云元数据端点 (169.254.169.254)。",
  },
  {
    pattern: /\[::ffff:169\.254\.169\.254\]/i,
    severity: "critical",
    title: "云元数据访问（IPv6 映射 - dotted）",
    description: "IPv6 映射地址访问云元数据端点 (169.254.169.254)。",
  },
  {
    pattern: /\[(?:0:){5}ffff:a9fe:a9fe\]/i,
    severity: "critical",
    title: "云元数据访问（IPv6 映射 - hex）",
    description: "IPv6 全零展开形式访问云元数据端点。",
  },
  {
    pattern: /\[::ffff:a9fe:a9fe\]/i,
    severity: "critical",
    title: "云元数据访问（IPv6 映射 - 压缩 hex）",
    description: "IPv6 压缩形式 hex 地址访问云元数据端点。",
  },
  {
    pattern: /\[::169\.254\.169\.254\]/i,
    severity: "critical",
    title: "云元数据访问（IPv4 兼容 IPv6）",
    description: "IPv4 兼容 IPv6 地址访问云元数据端点——绕过 IPv6 映射检测。",
  },
  // IPv6-mapped with dotted-decimal IPv4 in expanded form
  {
    pattern: /\[0{1,4}:0{1,4}:0{1,4}:0{1,4}:0{1,4}:ffff:169\.254\.169\.254\]/i,
    severity: "critical",
    title: "云元数据访问（IPv6 展开 dotted）",
    description: "IPv6 完全展开形式（dotted-decimal）访问云元数据端点。",
  },
  // Mixed hex/decimal IP encoding (requires at least one 0x octet, e.g., 0xa9.254.0xa9.254)
  {
    pattern: /(?:https?|ftp|wss?):\/\/(?:(?:0x[0-9a-fA-F]+\.(?:0x[0-9a-fA-F]+|\d{1,3})\.(?:0x[0-9a-fA-F]+|\d{1,3})\.(?:0x[0-9a-fA-F]+|\d{1,3}))|(?:(?:0x[0-9a-fA-F]+|\d{1,3})\.(?:0x[0-9a-fA-F]+|\d{1,3})\.(?:0x[0-9a-fA-F]+|\d{1,3})\.0x[0-9a-fA-F]+))/i,
    severity: "high",
    title: "混合编码 IP 连接",
    description: "通过混合十六进制/十进制编码 IP 地址连接——绕过域名检测的 C2 手法。",
  },

  // Tencent Cloud metadata
  {
    pattern: /\bmetadata\.tencentyun\.com\b/i,
    severity: "critical",
    title: "腾讯云元数据访问",
    description: "访问腾讯云 CVM 元数据服务 (metadata.tencentyun.com)。",
  },

  // DNS wildcard services that resolve to embedded IPs (metadata bypass)
  {
    pattern: /169\.254\.169\.254\.(?:nip|sslip|xip)\.io/i,
    severity: "critical",
    title: "DNS 通配符元数据绕过",
    description: "通过 DNS 通配符服务 (nip.io/sslip.io) 访问云元数据——绕过域名检测。",
  },

  // Alibaba Cloud metadata
  {
    pattern: /100\.100\.100\.200/,
    severity: "critical",
    title: "阿里云元数据访问",
    description: "访问阿里云 ECS 元数据服务 (100.100.100.200)。",
  },

  // AWS ECS task metadata
  {
    pattern: /169\.254\.170\.2/,
    severity: "critical",
    title: "AWS ECS 任务元数据访问",
    description: "访问 AWS ECS 任务元数据端点 (169.254.170.2)——可获取任务角色凭证。",
  },

  // SSRF loopback/localhost access
  {
    pattern: /(?:https?|ftp|wss?|gopher|ldap|dict|sftp|telnet|tftp):\/\/(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0)(?:[:/]|$)/i,
    severity: "medium",
    title: "本地回环地址访问",
    description: "连接到 localhost/127.x.x.x/0.0.0.0——可能是 SSRF 攻击。",
  },
  // Short-form loopback IP addresses (127.1, 127.0.1, etc.)
  {
    pattern: /(?:https?|ftp|wss?|gopher|ldap|dict|sftp|telnet|tftp):\/\/127\.\d{1,3}(?:\.\d{1,3})?(?:[:/]|$)/i,
    severity: "medium",
    title: "短格式回环地址访问",
    description: "通过短格式回环 IP（127.1 等）连接——SSRF 绕过手法。",
  },
  // Bare 0 as IP (resolves to 0.0.0.0 in most HTTP libraries)
  {
    pattern: /(?:https?|ftp|wss?|gopher|ldap|dict|sftp|telnet|tftp):\/\/0(?:[:/]|$)/,
    severity: "medium",
    title: "零地址访问",
    description: "连接到 0 地址（解析为 0.0.0.0）——SSRF 绕过手法。",
  },
  {
    pattern: /(?:https?|ftp|wss?|gopher|ldap|dict|sftp|telnet|tftp):\/\/\[::1?\](?:[:/]|$)/i,
    severity: "medium",
    title: "IPv6 本地回环地址访问",
    description: "连接到 IPv6 localhost (::1)——可能是 SSRF 攻击。",
  },
];

// ── URL 提取 ──

const MAX_URL_LEN = 4096;

const MAX_WALK_DEPTH = 10;
const MAX_URL_COUNT = 200;
const MAX_DECODE_PASSES = 5;

/**
 * Iteratively decode a percent-encoded string until it stabilises or the
 * iteration budget is exhausted.  This prevents bypass via double- (or
 * triple-, etc.) encoding such as `https%253A%252F%252Fevil.com`.
 */
function fullyDecodeURI(raw: string): string {
  // Apply NFKC normalization to prevent bypass via fullwidth Unicode characters
  // (consistent with PathGuard's normalization in path-guard.ts)
  // Strip null bytes that could split domain names and evade pattern matching
  let decoded = raw.normalize("NFKC").replace(/\0/g, "");
  for (let i = 0; i < MAX_DECODE_PASSES; i++) {
    let next: string;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      // Malformed percent-encoding (e.g., %zz): decode valid %XX sequences
      // individually so a malformed prefix can't protect encoded payloads.
      next = decoded.replace(/%[0-9A-Fa-f]{2}/g, (m) => {
        try { return decodeURIComponent(m); } catch { return m; }
      });
    }
    if (next === decoded) break; // stable
    decoded = next;
  }
  return decoded;
}

function extractUrls(params: Record<string, unknown>): string[] {
  const seen = new Set<string>();
  // Primary: known URL parameter keys
  const keys = ["url", "uri", "href", "endpoint", "target", "address", "host", "domain",
    "webhook", "callback", "redirect", "base_url", "api_endpoint", "server", "remote"];
  const lowerParams: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(params)) lowerParams[k.toLowerCase()] = v;
  for (const key of keys) {
    const val = lowerParams[key];
    if (typeof val === "string" && val.length > 0) {
      seen.add(val.length > MAX_URL_LEN ? val.slice(0, MAX_URL_LEN) : val);
    }
  }

  // Secondary: scan ALL string values recursively for embedded URLs
  function walk(val: unknown, depth: number): void {
    if (depth > MAX_WALK_DEPTH || seen.size >= MAX_URL_COUNT) return;
    if (typeof val === "string" && val.length > 8) {
      const capped = val.length > MAX_URL_LEN ? val.slice(0, MAX_URL_LEN) : val;
      const matches = capped.match(/(?:(?:https?|ftp|wss?|stratum\+tcp|gopher|ldap|dict|sftp|telnet|tftp):\/\/|\/\/(?=[^\s"'/]*[.:]))[^\s"']+/gi);
      if (matches) {
        for (const m of matches) {
          if (seen.size >= MAX_URL_COUNT) break;
          seen.add(m);
        }
      }
    } else if (Array.isArray(val)) {
      for (const item of val) walk(item, depth + 1);
    } else if (val && typeof val === "object") {
      for (const v of Object.values(val as Record<string, unknown>)) walk(v, depth + 1);
    }
  }

  walk(params, 0);
  return Array.from(seen);
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

      for (const rawUrl of urls) {
        // Fully decode percent-encoded URLs (including double/triple encoding)
        // so patterns like \bpastebin\.com\b match even when the domain is
        // encoded (e.g. pastebin%2Ecom or pastebin%252Ecom).
        const url = fullyDecodeURI(rawUrl);
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
          toolParams: redactSensitiveValues(ctx.toolParams),
          skillName: ctx.skillName,
          sessionId: ctx.sessionId,
          agentId: ctx.agentId,
          matchedPattern: rule.pattern.source,
        },
      };
    },
  };
}
