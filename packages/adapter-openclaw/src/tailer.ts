/**
 * JSONL Session Log Tailer
 *
 * 实时监听 OpenClaw 会话日志文件（~/.openclaw/sessions/*.jsonl），
 * 使用 fs.watch 实现跨平台（Windows/macOS/Linux）。
 */

import { watch, stat, open } from "node:fs/promises";
import { join } from "node:path";
import { homedir } from "node:os";
import { EventEmitter } from "node:events";

export interface SessionLogEntry {
  role: "user" | "assistant" | "tool";
  type?: string;
  text?: string;
  toolName?: string;
  toolCallId?: string;
  toolParams?: Record<string, unknown>;
  toolResult?: unknown;
  toolError?: string;
  timestamp?: number;
  metadata?: Record<string, unknown>;
  sessionId?: string;
}

export class SessionLogTailer extends EventEmitter {
  private sessionBaseDir: string;
  private fileOffsets = new Map<string, number>();
  private abortController = new AbortController();

  constructor(sessionBaseDir?: string) {
    super();
    this.sessionBaseDir =
      sessionBaseDir ?? join(homedir(), ".openclaw", "sessions");
  }

  async watchSessionDir(): Promise<void> {
    try {
      const watcher = watch(this.sessionBaseDir, {
        recursive: true,
        signal: this.abortController.signal,
      });
      for await (const event of watcher) {
        if (event.filename?.endsWith(".jsonl") && event.eventType === "change") {
          const fullPath = join(this.sessionBaseDir, event.filename);
          await this.readNewLines(fullPath);
        }
      }
    } catch (err: any) {
      if (err.name === "AbortError") return;
      this.emit("error", err);
    }
  }

  async readNewLines(filePath: string): Promise<void> {
    try {
      const fileStat = await stat(filePath);
      const offset = this.fileOffsets.get(filePath) ?? 0;
      if (fileStat.size <= offset) return;

      const fd = await open(filePath, "r");
      try {
        const buf = Buffer.alloc(fileStat.size - offset);
        await fd.read(buf, 0, buf.length, offset);
        this.fileOffsets.set(filePath, fileStat.size);

        for (const line of buf.toString("utf-8").split("\n")) {
          if (!line.trim()) continue;
          try {
            this.emit("entry", JSON.parse(line) as SessionLogEntry, filePath);
          } catch { /* 跳过不完整的 JSON */ }
        }
      } finally {
        await fd.close();
      }
    } catch (err) {
      this.emit("error", err);
    }
  }

  stop(): void {
    this.abortController.abort();
    this.fileOffsets.clear();
  }
}
