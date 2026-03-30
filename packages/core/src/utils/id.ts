import { randomUUID } from "node:crypto";

/** 生成安全事件 ID：cpc_ + UUID v4（122 bit 熵） */
export function generateEventId(): string {
  return `cpc_${randomUUID()}`;
}
