/**
 * NetworkGuard — 可疑网络访问检测
 *
 * 检测对数据外泄常用服务、匿名网络、
 * 裸 IP 地址、挖矿池等的网络访问。
 */
import type { SecurityRule } from "../types.js";
export declare function createNetworkGuardRule(blockedDomains?: string[]): SecurityRule;
//# sourceMappingURL=network-guard.d.ts.map