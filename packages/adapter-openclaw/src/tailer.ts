/**
 * JSONL Session Log Tailer
 *
 * 实时监听 OpenClaw 会话日志文件（~/.openclaw/sessions/*.jsonl），
 * 使用 fs.watch 实现跨平台（Windows/macOS/Linux）。
 */

import { watch, stat, open } from "node:fs/promises";
import { join, resolve, sep } from "node:path";
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
  private pendingReads = new Set<string>();
  private static readonly MAX_TRACKED_FILES = 500;

  constructor(sessionBaseDir?: string) {
    super();
    this.sessionBaseDir =
      sessionBaseDir ?? join(homedir(), ".openclaw", "sessions");
  }

  async watchSessionDir(): Promise<void> {
    // Reset abort controller if previously stopped, allowing restart
    if (this.abortController.signal.aborted) {
      this.abortController = new AbortController();
    }
    try {
      const watcher = watch(this.sessionBaseDir, {
        recursive: true,
        signal: this.abortController.signal,
      });
      for await (const event of watcher) {
        if (event.filename?.endsWith(".jsonl") && event.eventType === "change") {
          const fullPath = join(this.sessionBaseDir, event.filename);
          if (!resolve(fullPath).startsWith(resolve(this.sessionBaseDir) + sep)) continue;
          await this.readNewLines(fullPath);
        }
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name === "AbortError") return;
      this.emit("error", err);
    }
  }

  async readNewLines(filePath: string): Promise<void> {
    // Guard against concurrent reads on the same file to prevent duplicate events
    if (this.pendingReads.has(filePath)) return;
    this.pendingReads.add(filePath);
    try {
      const fileStat = await stat(filePath);
      let offset = this.fileOffsets.get(filePath) ?? 0;
      // Detect file truncation/rotation: if file shrunk, reset offset
      if (fileStat.size < offset) {
        this.fileOffsets.set(filePath, 0);
        offset = 0;
      }
      if (fileStat.size <= offset) return;

      // Cap read size to prevent excessive memory allocation from huge log files
      const MAX_READ_SIZE = 10 * 1024 * 1024; // 10MB
      const readSize = Math.min(fileStat.size - offset, MAX_READ_SIZE);

      // Evict oldest entries if tracking too many files
      if (this.fileOffsets.size > SessionLogTailer.MAX_TRACKED_FILES) {
        const entries = [...this.fileOffsets.entries()];
        // Remove the first half (oldest entries by insertion order)
        for (let i = 0; i < entries.length / 2; i++) {
          this.fileOffsets.delete(entries[i][0]);
        }
      }

      const fd = await open(filePath, "r");
      try {
        const buf = Buffer.alloc(readSize);
        const { bytesRead } = await fd.read(buf, 0, buf.length, offset);
        if (bytesRead === 0) return;
        const text = buf.subarray(0, bytesRead).toString("utf-8");

        // Only advance offset to the last complete line to avoid losing partial writes
        const lastNewline = text.lastIndexOf("\n");
        if (lastNewline === -1) {
          // No complete line yet, don't advance offset
          return;
        }
        this.fileOffsets.set(filePath, offset + lastNewline + 1);

        for (const line of text.substring(0, lastNewline).split("\n")) {
          if (!line.trim()) continue;
          try {
            this.emit("entry", JSON.parse(line) as SessionLogEntry, filePath);
          } catch { /* 跳过不完整的 JSON */ }
        }
      } finally {
        try { await fd.close(); } catch { /* fd already closed or invalid */ }
      }
    } catch (err) {
      // Clean up offset tracking for deleted files
      if (err && typeof err === "object" && "code" in err && err.code === "ENOENT") {
        this.fileOffsets.delete(filePath);
        return;
      }
      this.emit("error", err);
    } finally {
      this.pendingReads.delete(filePath);
    }
  }

  stop(): void {
    this.abortController.abort();
    this.fileOffsets.clear();
  }
}
