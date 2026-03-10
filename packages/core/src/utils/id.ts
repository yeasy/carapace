import { randomBytes } from "node:crypto";

/** 生成安全事件 ID：cpc_ + 12 位十六进制（48 bit 熵） */
export function generateEventId(): string {
  return `cpc_${randomBytes(6).toString("hex")}`;
}
