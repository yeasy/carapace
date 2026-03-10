/**
 * Carapace Core — 告警路由器
 *
 * 将安全事件分发到多个告警渠道（console、webhook、logfile）。
 * 内置 5 分钟去重窗口，防止同类事件刷屏。
 */
import { createHash } from "node:crypto";
import { appendFile, mkdir } from "node:fs/promises";
import { dirname } from "node:path";
// ─── Console Sink ────────────────────────────────────────────────
const SEVERITY_COLORS = {
    critical: "\x1b[41m\x1b[37m", // 白字红底
    high: "\x1b[31m", // 红色
    medium: "\x1b[33m", // 黄色
    low: "\x1b[36m", // 青色
    info: "\x1b[90m", // 灰色
};
const RESET = "\x1b[0m";
export class ConsoleSink {
    name = "console";
    async send(payload) {
        const { event } = payload;
        const color = SEVERITY_COLORS[event.severity];
        const prefix = `${color}[CARAPACE ${event.severity.toUpperCase()}]${RESET}`;
        const action = event.action === "blocked" ? " 🛡️ BLOCKED" : "";
        process.stderr.write(`${prefix}${action} ${event.title}\n` +
            `  ${event.description}\n` +
            `  tool=${event.toolName ?? "?"} skill=${event.skillName ?? "?"} rule=${event.ruleName ?? "?"}\n\n`);
    }
}
// ─── Webhook Sink ────────────────────────────────────────────────
export class WebhookSink {
    url;
    name = "webhook";
    constructor(url) {
        this.url = url;
    }
    async send(payload) {
        try {
            await fetch(this.url, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    source: "carapace",
                    version: "0.1.0",
                    event: {
                        id: payload.event.id,
                        timestamp: new Date(payload.event.timestamp).toISOString(),
                        severity: payload.event.severity,
                        category: payload.event.category,
                        title: payload.event.title,
                        description: payload.event.description,
                        toolName: payload.event.toolName,
                        skillName: payload.event.skillName,
                        action: payload.event.action,
                    },
                }),
                signal: AbortSignal.timeout(5000),
            });
        }
        catch {
            // Webhook 失败不应阻塞主流程
        }
    }
}
// ─── LogFile Sink ────────────────────────────────────────────────
export class LogFileSink {
    filePath;
    name = "logfile";
    initialized = false;
    constructor(filePath) {
        this.filePath = filePath;
    }
    async send(payload) {
        try {
            if (!this.initialized) {
                await mkdir(dirname(this.filePath), { recursive: true });
                this.initialized = true;
            }
            await appendFile(this.filePath, JSON.stringify(payload.event) + "\n");
        }
        catch {
            // 写入失败不阻塞
        }
    }
}
// ─── 告警路由器 ──────────────────────────────────────────────────
export class AlertRouter {
    sinks = [];
    dedup = new Map();
    dedupWindowMs = 5 * 60 * 1000; // 5 分钟去重窗口
    addSink(sink) {
        this.sinks.push(sink);
    }
    removeSink(name) {
        this.sinks = this.sinks.filter((s) => s.name !== name);
    }
    /**
     * 发送安全事件到所有已注册的 sink。
     * 5 分钟内同一 rule+tool+params 的事件会被去重。
     */
    async send(event) {
        // 去重检查
        const dedupKey = this.computeDedupKey(event);
        const now = Date.now();
        const lastSeen = this.dedup.get(dedupKey);
        if (lastSeen && now - lastSeen < this.dedupWindowMs) {
            return; // 抑制重复告警
        }
        this.dedup.set(dedupKey, now);
        this.cleanupDedup(now);
        const payload = {
            event,
            summary: `[${event.severity.toUpperCase()}] ${event.title}`,
            actionTaken: event.action,
        };
        // 并行发送到所有 sink
        await Promise.allSettled(this.sinks.map((sink) => sink.send(payload)));
    }
    computeDedupKey(event) {
        const raw = `${event.ruleName}:${event.toolName}:${JSON.stringify(event.toolParams ?? {})}`;
        return createHash("sha256").update(raw).digest("hex").slice(0, 16);
    }
    cleanupDedup(now) {
        if (this.dedup.size < 100)
            return; // 不频繁清理
        for (const [key, ts] of this.dedup) {
            if (now - ts > this.dedupWindowMs) {
                this.dedup.delete(key);
            }
        }
    }
}
//# sourceMappingURL=alerter.js.map