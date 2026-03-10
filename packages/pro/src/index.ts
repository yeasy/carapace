/**
 * @carapace/pro — Pro/Enterprise 功能入口
 *
 * License: Business Source License 1.1
 * 代码可见可审计，但商业使用需购买许可。
 */

export { verifyLicense, isProLicensed, isEnterpriseLicensed } from "./license.js";
export type { LicensePayload, LicenseStatus } from "./license.js";

// TODO v0.2: Dashboard Web UI
// TODO v0.2: SIEM 连接器（Splunk, ELK, Datadog）
// TODO v0.3: 集中策略管理
// TODO v0.3: ML 异常检测
