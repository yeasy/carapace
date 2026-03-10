/**
 * Carapace Core — 告警路由器
 *
 * 将安全事件分发到多个告警渠道（console、webhook、logfile）。
 * 内置 5 分钟去重窗口，防止同类事件刷屏。
 */
import type { SecurityEvent, AlertPayload, AlertSink } from "./types.js";
export declare class ConsoleSink implements AlertSink {
    name: string;
    send(payload: AlertPayload): Promise<void>;
}
export declare class WebhookSink implements AlertSink {
    private url;
    name: string;
    constructor(url: string);
    send(payload: AlertPayload): Promise<void>;
}
export declare class LogFileSink implements AlertSink {
    private filePath;
    name: string;
    private initialized;
    constructor(filePath: string);
    send(payload: AlertPayload): Promise<void>;
}
export declare class AlertRouter {
    private sinks;
    private dedup;
    private dedupWindowMs;
    addSink(sink: AlertSink): void;
    removeSink(name: string): void;
    /**
     * 发送安全事件到所有已注册的 sink。
     * 5 分钟内同一 rule+tool+params 的事件会被去重。
     */
    send(event: SecurityEvent): Promise<void>;
    private computeDedupKey;
    private cleanupDedup;
}
//# sourceMappingURL=alerter.d.ts.map