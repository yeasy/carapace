/**
 * PathGuard — 敏感文件路径访问检测
 *
 * 检测工具调用中对敏感文件路径的访问：
 * SSH 密钥、云凭证、浏览器数据、加密钱包、系统认证文件。
 * 跨平台：覆盖 Windows、macOS、Linux 路径。
 */
import type { SecurityRule } from "../types.js";
export declare function createPathGuardRule(additionalPatterns?: string[]): SecurityRule;
//# sourceMappingURL=path-guard.d.ts.map