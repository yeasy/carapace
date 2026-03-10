/**
 * Carapace Pro — License 验证
 *
 * 使用 Ed25519 非对称签名，离线验证。
 * License key 格式：CARAPACE-<plan>-<base64url(payload)>.<base64url(signature)>
 *
 * 签发流程（你的私钥，不在代码里）：
 *   1. 构造 JSON payload: { user, plan, exp, seats?, issuedAt }
 *   2. base64url 编码 payload
 *   3. 用 Ed25519 私钥对编码后的 payload 签名
 *   4. 拼接：CARAPACE-PRO-<payloadB64>.<signatureB64>
 *
 * 验证流程（此文件，公钥硬编码）：
 *   1. 解析 key，提取 payloadB64 和 signatureB64
 *   2. 用公钥验证签名
 *   3. 检查过期时间
 */

import { verify } from "node:crypto";

// ── 公钥（Ed25519）──
// 替换为你的实际公钥。生成方式：
//   openssl genpkey -algorithm Ed25519 -out carapace-private.pem
//   openssl pkey -in carapace-private.pem -pubout -out carapace-public.pem
const PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAPlaceholderKeyReplaceWithYourActualEd25519PublicKey=
-----END PUBLIC KEY-----`;

// ── License 载荷类型 ──

export interface LicensePayload {
  /** 用户邮箱 */
  user: string;
  /** 许可计划 */
  plan: "pro" | "enterprise";
  /** 过期时间（Unix 秒） */
  exp: number;
  /** Enterprise 座位数 */
  seats?: number;
  /** 签发时间（Unix 秒） */
  issuedAt: number;
}

export interface LicenseStatus {
  valid: boolean;
  payload?: LicensePayload;
  error?: string;
}

// ── 验证函数 ──

/**
 * 验证 Carapace license key。
 * 纯离线验证，不需要网络。
 */
export function verifyLicense(key: string): LicenseStatus {
  try {
    // 去掉前缀 "CARAPACE-PRO-" 或 "CARAPACE-ENTERPRISE-"
    const stripped = key.replace(/^CARAPACE-(PRO|ENTERPRISE)-/i, "");
    const dotIndex = stripped.lastIndexOf(".");
    if (dotIndex === -1) {
      return { valid: false, error: "License key 格式无效" };
    }

    const payloadB64 = stripped.slice(0, dotIndex);
    const signatureB64 = stripped.slice(dotIndex + 1);

    // 验证签名
    const isValid = verify(
      null, // Ed25519 不需要指定 hash 算法
      Buffer.from(payloadB64),
      PUBLIC_KEY,
      Buffer.from(signatureB64, "base64url")
    );

    if (!isValid) {
      return { valid: false, error: "签名验证失败" };
    }

    // 解码 payload
    const payload = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf-8")
    ) as LicensePayload;

    // 检查过期
    const nowSec = Math.floor(Date.now() / 1000);
    if (payload.exp < nowSec) {
      return {
        valid: false,
        payload,
        error: `License 已过期 (${new Date(payload.exp * 1000).toISOString()})`,
      };
    }

    // 检查必要字段
    if (!payload.user || !payload.plan || !payload.exp) {
      return { valid: false, error: "License payload 缺少必要字段" };
    }

    return { valid: true, payload };
  } catch (err) {
    return {
      valid: false,
      error: `License 验证异常: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

/**
 * 检查是否为 Pro 或更高级别。
 */
export function isProLicensed(key?: string): boolean {
  if (!key) return false;
  const status = verifyLicense(key);
  return status.valid === true;
}

/**
 * 检查是否为 Enterprise 级别。
 */
export function isEnterpriseLicensed(key?: string): boolean {
  if (!key) return false;
  const status = verifyLicense(key);
  return status.valid === true && status.payload?.plan === "enterprise";
}
