/**
 * redactSensitiveValues — 对工具参数中的敏感数据进行脱敏
 *
 * 深拷贝 params 对象，在所有字符串值中查找并替换常见敏感模式为 [REDACTED]。
 * 仅替换匹配的子串，不会整体替换字符串。
 * 绝不修改原始对象。
 */

const SENSITIVE_PATTERNS: RegExp[] = [
  // AWS Access Key IDs
  /AKIA[0-9A-Z]{16}/g,
  // API keys / tokens / secrets (sk-xxx, pk_xxx, api_key_xxx, token-xxx, etc.)
  // Require a separator (_-) after the prefix to avoid false positives on normal words
  /(?:sk|pk|api|token|key|secret|password|passwd|auth)[_-][a-zA-Z0-9]{16,}/gi,
  // PEM private keys (header + body + footer)
  /-----BEGIN[A-Z\s]*PRIVATE KEY-----[\s\S]*?-----END[A-Z\s]*PRIVATE KEY-----/g,
  // PEM private key header only (fallback when END marker is missing/truncated)
  /-----BEGIN[A-Z\s]*PRIVATE KEY-----/g,
  // Passwords/secrets in environment variable exports
  /(?:PASSWORD|SECRET|TOKEN|API_KEY)\s*=\s*\S+/g,
  // JWT tokens (three base64url-encoded segments separated by dots)
  /eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/g,
  // Slack tokens (xoxb-xxx, xoxp-xxx, xoxs-xxx, xoxa-xxx, xoxr-xxx)
  /xox[bpsar]-[0-9a-zA-Z-]{10,}/g,
  // GitHub fine-grained personal access tokens
  /github_pat_[a-zA-Z0-9]{22,}/g,
  // Connection strings with embedded credentials (postgres, mysql, mongodb, redis, amqp)
  /(?:postgres|mysql|mongodb|redis|amqp)(?:\+\w+)?:\/\/[^:]+:[^@\s]+@/gi,
  // Bearer/Basic tokens in authorization headers
  /(?:Bearer|Basic|Authorization:?)\s+[a-zA-Z0-9._~+\/-]{16,}/gi,
  // Anthropic API keys (sk-ant-xxx)
  /sk-ant-[a-zA-Z0-9_-]{20,}/g,
  // Google API keys (AIzaSy...)
  /AIzaSy[a-zA-Z0-9_-]{33}/g,
  // GitHub OAuth tokens (gho_xxx)
  /gho_[a-zA-Z0-9]{36,}/g,
];

/**
 * Deep-clone `params` and replace sensitive substrings with `[REDACTED]`.
 * Never mutates the original object.
 */
export function redactSensitiveValues(
  params: Record<string, unknown>,
): Record<string, unknown> {
  // Deep clone to avoid mutating the original
  // structuredClone handles more types and fails gracefully on circular refs
  let cloned: Record<string, unknown>;
  try {
    cloned = structuredClone(params);
  } catch {
    // Fallback for environments without structuredClone or circular refs
    try {
      cloned = JSON.parse(JSON.stringify(params)) as Record<string, unknown>;
    } catch {
      return { _redactionError: "[unable to clone params]" };
    }
  }
  redactWalk(cloned);
  return cloned;
}

// Cap input length to prevent ReDoS on very long strings
const MAX_REDACT_LEN = 16384;

function redactString(value: string): string {
  if (value.length <= MAX_REDACT_LEN) {
    let result = value;
    for (const pattern of SENSITIVE_PATTERNS) {
      pattern.lastIndex = 0;
      result = result.replace(pattern, "[REDACTED]");
    }
    return result;
  }
  // Sliding-window redaction: scan the full string in overlapping chunks
  // (consistent with data-exfil and prompt-injection detection rules).
  // Collect redaction ranges from each chunk, then apply once on the original
  // string to avoid boundary corruption when [REDACTED] differs in length.
  const chunkSize = MAX_REDACT_LEN;
  const overlap = 512;
  const step = chunkSize - overlap;
  const ranges: Array<[number, number]> = [];
  for (let i = 0; i < value.length; i += step) {
    const chunk = value.slice(i, i + chunkSize);
    for (const pattern of SENSITIVE_PATTERNS) {
      pattern.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = pattern.exec(chunk)) !== null) {
        ranges.push([i + m.index, i + m.index + m[0].length]);
        if (!pattern.global) break;
      }
    }
  }
  if (ranges.length === 0) return value;
  // Merge overlapping ranges and apply replacements right-to-left
  ranges.sort((a, b) => a[0] - b[0] || b[1] - a[1]);
  const merged: Array<[number, number]> = [ranges[0]];
  for (let i = 1; i < ranges.length; i++) {
    const last = merged[merged.length - 1];
    if (ranges[i][0] <= last[1]) {
      last[1] = Math.max(last[1], ranges[i][1]);
    } else {
      merged.push(ranges[i]);
    }
  }
  let result = value;
  for (let i = merged.length - 1; i >= 0; i--) {
    result = result.slice(0, merged[i][0]) + "[REDACTED]" + result.slice(merged[i][1]);
  }
  return result;
}

const MAX_REDACT_DEPTH = 20;

function redactWalk(obj: unknown, depth = 0): void {
  if (depth > MAX_REDACT_DEPTH) return;
  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      if (typeof obj[i] === "string") {
        obj[i] = redactString(obj[i]);
      } else if (obj[i] && typeof obj[i] === "object") {
        redactWalk(obj[i], depth + 1);
      }
    }
  } else if (obj && typeof obj === "object") {
    const record = obj as Record<string, unknown>;
    for (const key of Object.keys(record)) {
      if (typeof record[key] === "string") {
        record[key] = redactString(record[key] as string);
      } else if (record[key] && typeof record[key] === "object") {
        redactWalk(record[key], depth + 1);
      }
    }
  }
}
