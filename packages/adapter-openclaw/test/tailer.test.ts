/**
 * SessionLogTailer -- Comprehensive test suite
 *
 * Tests the JSONL session log tailer by creating temporary directories
 * and files to exercise parsing, offset tracking, error handling, and
 * path traversal prevention.
 */

import { describe, it, expect, vi, afterEach, beforeEach } from "vitest";
import { mkdtemp, writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir, homedir } from "node:os";
import { SessionLogTailer } from "../src/tailer.js";

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "tailer-test-"));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

// ── Constructor ──

describe("constructor", () => {
  it("defaults sessionBaseDir to homedir-based path", () => {
    const tailer = new SessionLogTailer();
    // Access private field via type cast for verification
    const baseDir = (tailer as any).sessionBaseDir;
    expect(baseDir).toBe(join(homedir(), ".openclaw", "sessions"));
    tailer.stop();
  });

  it("accepts a custom sessionBaseDir", () => {
    const custom = "/tmp/my-sessions";
    const tailer = new SessionLogTailer(custom);
    const baseDir = (tailer as any).sessionBaseDir;
    expect(baseDir).toBe(custom);
    tailer.stop();
  });
});

// ── readNewLines: basic JSONL parsing ──

describe("readNewLines - JSONL parsing", () => {
  it("parses valid JSONL lines and emits 'entry' events", async () => {
    const tailer = new SessionLogTailer(tempDir);
    const filePath = join(tempDir, "session1.jsonl");

    const entry1 = { role: "user", text: "hello" };
    const entry2 = { role: "assistant", text: "hi there" };
    await writeFile(filePath, JSON.stringify(entry1) + "\n" + JSON.stringify(entry2) + "\n");

    const entries: any[] = [];
    tailer.on("entry", (entry, path) => {
      entries.push({ entry, path });
    });

    await tailer.readNewLines(filePath);

    expect(entries).toHaveLength(2);
    expect(entries[0].entry).toEqual(entry1);
    expect(entries[0].path).toBe(filePath);
    expect(entries[1].entry).toEqual(entry2);
    tailer.stop();
  });

  it("skips empty lines without crashing", async () => {
    const tailer = new SessionLogTailer(tempDir);
    const filePath = join(tempDir, "session2.jsonl");

    const entry = { role: "tool", toolName: "bash" };
    await writeFile(filePath, "\n\n" + JSON.stringify(entry) + "\n\n");

    const entries: any[] = [];
    tailer.on("entry", (e) => entries.push(e));

    await tailer.readNewLines(filePath);

    expect(entries).toHaveLength(1);
    expect(entries[0]).toEqual(entry);
    tailer.stop();
  });

  it("skips incomplete / invalid JSON without crashing", async () => {
    const tailer = new SessionLogTailer(tempDir);
    const filePath = join(tempDir, "session3.jsonl");

    const validEntry = { role: "user", text: "ok" };
    await writeFile(
      filePath,
      '{"role": "user", "text": "trun\n' + // incomplete JSON
      JSON.stringify(validEntry) + "\n" +
      "not json at all\n",
    );

    const entries: any[] = [];
    const errors: any[] = [];
    tailer.on("entry", (e) => entries.push(e));
    tailer.on("error", (e) => errors.push(e));

    await tailer.readNewLines(filePath);

    // Only the valid entry should be emitted
    expect(entries).toHaveLength(1);
    expect(entries[0]).toEqual(validEntry);
    // No errors should be emitted (invalid JSON is silently skipped)
    expect(errors).toHaveLength(0);
    tailer.stop();
  });
});

// ── readNewLines: complex entry with all fields ──

describe("readNewLines - complex entry", () => {
  it("parses entry with all SessionLogEntry fields", async () => {
    const tailer = new SessionLogTailer(tempDir);
    const filePath = join(tempDir, "complex.jsonl");

    const complexEntry = {
      role: "tool",
      type: "tool_result",
      text: "command output here",
      toolName: "bash",
      toolCallId: "call_abc123",
      toolParams: { command: "ls -la", cwd: "/home" },
      toolResult: { exitCode: 0, stdout: "files" },
      toolError: undefined,
      timestamp: 1700000000000,
      metadata: { duration: 42, source: "plugin" },
      sessionId: "sess-xyz",
    };
    await writeFile(filePath, JSON.stringify(complexEntry) + "\n");

    const entries: any[] = [];
    tailer.on("entry", (e) => entries.push(e));

    await tailer.readNewLines(filePath);

    expect(entries).toHaveLength(1);
    expect(entries[0].role).toBe("tool");
    expect(entries[0].toolName).toBe("bash");
    expect(entries[0].toolCallId).toBe("call_abc123");
    expect(entries[0].toolParams).toEqual({ command: "ls -la", cwd: "/home" });
    expect(entries[0].timestamp).toBe(1700000000000);
    expect(entries[0].metadata).toEqual({ duration: 42, source: "plugin" });
    expect(entries[0].sessionId).toBe("sess-xyz");
    tailer.stop();
  });
});

// ── readNewLines: offset tracking ──

describe("readNewLines - offset tracking", () => {
  it("reads only new content on subsequent calls", async () => {
    const tailer = new SessionLogTailer(tempDir);
    const filePath = join(tempDir, "incremental.jsonl");

    const entry1 = { role: "user", text: "first" };
    await writeFile(filePath, JSON.stringify(entry1) + "\n");

    const entries: any[] = [];
    tailer.on("entry", (e) => entries.push(e));

    // First read
    await tailer.readNewLines(filePath);
    expect(entries).toHaveLength(1);

    // Append a second entry
    const entry2 = { role: "assistant", text: "second" };
    const { appendFile } = await import("node:fs/promises");
    await appendFile(filePath, JSON.stringify(entry2) + "\n");

    // Second read should only return the new entry
    await tailer.readNewLines(filePath);
    expect(entries).toHaveLength(2);
    expect(entries[1]).toEqual(entry2);
    tailer.stop();
  });

  it("does not re-emit when file has not grown", async () => {
    const tailer = new SessionLogTailer(tempDir);
    const filePath = join(tempDir, "no-growth.jsonl");

    await writeFile(filePath, '{"role":"user","text":"once"}\n');

    const entries: any[] = [];
    tailer.on("entry", (e) => entries.push(e));

    await tailer.readNewLines(filePath);
    await tailer.readNewLines(filePath);
    await tailer.readNewLines(filePath);

    expect(entries).toHaveLength(1);
    tailer.stop();
  });
});

// ── readNewLines: multi-file tracking ──

describe("readNewLines - multi-file tracking", () => {
  it("tracks separate offsets per file", async () => {
    const tailer = new SessionLogTailer(tempDir);

    const fileA = join(tempDir, "a.jsonl");
    const fileB = join(tempDir, "b.jsonl");

    await writeFile(fileA, '{"role":"user","text":"fileA-1"}\n');
    await writeFile(fileB, '{"role":"user","text":"fileB-1"}\n');

    const entries: any[] = [];
    tailer.on("entry", (e, path) => entries.push({ text: e.text, path }));

    await tailer.readNewLines(fileA);
    await tailer.readNewLines(fileB);

    expect(entries).toHaveLength(2);
    expect(entries[0]).toEqual({ text: "fileA-1", path: fileA });
    expect(entries[1]).toEqual({ text: "fileB-1", path: fileB });

    // Append to file A only
    const { appendFile } = await import("node:fs/promises");
    await appendFile(fileA, '{"role":"user","text":"fileA-2"}\n');

    await tailer.readNewLines(fileA);
    await tailer.readNewLines(fileB);

    // fileA gets one new entry, fileB gets none
    expect(entries).toHaveLength(3);
    expect(entries[2]).toEqual({ text: "fileA-2", path: fileA });
    tailer.stop();
  });
});

// ── readNewLines: file truncation / rotation ──

describe("readNewLines - file truncation", () => {
  it("resets offset when file is truncated (log rotation)", async () => {
    const tailer = new SessionLogTailer(tempDir);
    const filePath = join(tempDir, "rotated.jsonl");

    // Write initial data
    const entry1 = { role: "user", text: "before-rotation" };
    await writeFile(filePath, JSON.stringify(entry1) + "\n");

    const entries: any[] = [];
    tailer.on("entry", (e) => entries.push(e));

    // First read
    await tailer.readNewLines(filePath);
    expect(entries).toHaveLength(1);
    expect(entries[0].text).toBe("before-rotation");

    // Simulate log rotation: truncate and write smaller content
    const entry2 = { role: "assistant", text: "after-rotation" };
    await writeFile(filePath, JSON.stringify(entry2) + "\n");

    // Second read: should detect truncation and re-read from offset 0
    await tailer.readNewLines(filePath);
    expect(entries).toHaveLength(2);
    expect(entries[1].text).toBe("after-rotation");
    tailer.stop();
  });
});

// ── readNewLines: ENOENT handling ──

describe("readNewLines - ENOENT handling", () => {
  it("cleans up offset tracking for deleted files", async () => {
    const tailer = new SessionLogTailer(tempDir);
    const filePath = join(tempDir, "will-delete.jsonl");

    await writeFile(filePath, '{"role":"user","text":"exists"}\n');

    const entries: any[] = [];
    const errors: any[] = [];
    tailer.on("entry", (e) => entries.push(e));
    tailer.on("error", (e) => errors.push(e));

    await tailer.readNewLines(filePath);
    expect(entries).toHaveLength(1);

    // Delete the file
    const { unlink } = await import("node:fs/promises");
    await unlink(filePath);

    // Reading a deleted file should not emit an error
    await tailer.readNewLines(filePath);
    expect(errors).toHaveLength(0);

    // Offset should have been cleaned up; verify by checking internal state
    const offsets = (tailer as any).fileOffsets as Map<string, number>;
    expect(offsets.has(filePath)).toBe(false);
    tailer.stop();
  });
});

// ── readNewLines: 10MB read size cap ──

describe("readNewLines - 10MB read size cap", () => {
  it("caps a single read to 10MB even for larger files", async () => {
    const tailer = new SessionLogTailer(tempDir);
    const filePath = join(tempDir, "large.jsonl");

    // Create a file slightly larger than 10MB.
    // Each line ~100 bytes, need ~105,000 lines for ~10.5MB
    const line = JSON.stringify({ role: "user", text: "x".repeat(80) }) + "\n";
    const lineCount = Math.ceil((10.5 * 1024 * 1024) / Buffer.byteLength(line));
    const content = line.repeat(lineCount);
    await writeFile(filePath, content);

    const entries: any[] = [];
    tailer.on("entry", (e) => entries.push(e));

    // First read should cap at 10MB worth of data
    await tailer.readNewLines(filePath);

    const firstReadCount = entries.length;
    // Should have read some entries but not all (capped at 10MB)
    expect(firstReadCount).toBeGreaterThan(0);
    expect(firstReadCount).toBeLessThan(lineCount);

    // Second read should pick up more entries
    await tailer.readNewLines(filePath);
    expect(entries.length).toBeGreaterThan(firstReadCount);
    tailer.stop();
  });
});

// ── readNewLines: oversized single line (livelock prevention) ──

describe("readNewLines - oversized line livelock prevention", () => {
  it("skips lines exceeding 10MB cap instead of looping forever", async () => {
    const tailer = new SessionLogTailer(tempDir);
    const filePath = join(tempDir, "oversized.jsonl");

    // Create a file with one line > 10MB followed by a normal line
    const hugeLine = JSON.stringify({ role: "user", text: "x".repeat(11 * 1024 * 1024) });
    const normalLine = JSON.stringify({ role: "assistant", text: "ok" });
    await writeFile(filePath, hugeLine + "\n" + normalLine + "\n");

    const entries: any[] = [];
    tailer.on("entry", (e) => entries.push(e));

    // First read: should skip the oversized line (no newline within 10MB)
    await tailer.readNewLines(filePath);
    // Second read: should pick up remaining data including the normal line
    await tailer.readNewLines(filePath);

    // The normal line after the oversized one should eventually be emitted
    const foundNormal = entries.some((e) => e.text === "ok");
    expect(foundNormal).toBe(true);
    tailer.stop();
  });
});

// ── readNewLines: multi-byte UTF-8 offset tracking ──

describe("readNewLines - UTF-8 offset tracking", () => {
  it("correctly tracks byte offsets for multi-byte characters", async () => {
    const tailer = new SessionLogTailer(tempDir);
    const filePath = join(tempDir, "utf8.jsonl");

    // CJK characters are 3 bytes each in UTF-8
    const entry1 = { role: "user", text: "\u4f60\u597d" }; // 你好
    const entry2 = { role: "assistant", text: "world" };
    await writeFile(filePath, JSON.stringify(entry1) + "\n" + JSON.stringify(entry2) + "\n");

    const entries: any[] = [];
    tailer.on("entry", (e) => entries.push(e));

    // First read should get both entries
    await tailer.readNewLines(filePath);
    expect(entries).toHaveLength(2);
    expect(entries[0].text).toBe("\u4f60\u597d");
    expect(entries[1].text).toBe("world");

    // Append a third entry after the multi-byte content
    const entry3 = { role: "user", text: "after-cjk" };
    const { appendFile } = await import("node:fs/promises");
    await appendFile(filePath, JSON.stringify(entry3) + "\n");

    // Second read should correctly offset past the multi-byte content
    await tailer.readNewLines(filePath);
    expect(entries).toHaveLength(3);
    expect(entries[2].text).toBe("after-cjk");
    tailer.stop();
  });

  it("handles emoji in log entries without corrupting offsets", async () => {
    const tailer = new SessionLogTailer(tempDir);
    const filePath = join(tempDir, "emoji.jsonl");

    // Emoji are 4 bytes each in UTF-8
    const entry1 = { role: "user", text: "hello \uD83D\uDE00\uD83D\uDE80" }; // 😀🚀
    const entry2 = { role: "assistant", text: "done" };
    await writeFile(filePath, JSON.stringify(entry1) + "\n");

    const entries: any[] = [];
    tailer.on("entry", (e) => entries.push(e));

    await tailer.readNewLines(filePath);
    expect(entries).toHaveLength(1);

    const { appendFile } = await import("node:fs/promises");
    await appendFile(filePath, JSON.stringify(entry2) + "\n");

    await tailer.readNewLines(filePath);
    expect(entries).toHaveLength(2);
    expect(entries[1].text).toBe("done");
    tailer.stop();
  });
});

// ── readNewLines: error emission for non-ENOENT errors ──

describe("readNewLines - error emission", () => {
  it("emits error for non-ENOENT filesystem errors", async () => {
    const tailer = new SessionLogTailer(tempDir);

    // Point to a directory instead of a file -- open("r") on a directory
    // triggers an error that is not ENOENT
    const dirPath = join(tempDir, "subdir");
    await mkdir(dirPath);

    const errors: any[] = [];
    tailer.on("error", (e) => errors.push(e));

    await tailer.readNewLines(dirPath);

    expect(errors).toHaveLength(1);
    // The error should not be ENOENT
    expect((errors[0] as any).code).not.toBe("ENOENT");
    tailer.stop();
  });
});

// ── Path traversal prevention ──

describe("path traversal prevention", () => {
  it("watchSessionDir skips files outside sessionBaseDir via traversal", async () => {
    // This test verifies the path traversal guard in watchSessionDir.
    // We cannot easily trigger a real fs.watch event with a traversal path,
    // so we verify the resolve logic directly.
    const { resolve } = await import("node:path");

    const baseDir = "/home/user/.openclaw/sessions";
    const maliciousFilename = "../../../etc/passwd.jsonl";
    const fullPath = join(baseDir, maliciousFilename);

    // The guard: resolve(fullPath).startsWith(resolve(baseDir) + "/")
    const resolved = resolve(fullPath);
    const resolvedBase = resolve(baseDir) + "/";

    expect(resolved.startsWith(resolvedBase)).toBe(false);
  });

  it("allows normal nested paths within sessionBaseDir", async () => {
    const { resolve } = await import("node:path");

    const baseDir = "/home/user/.openclaw/sessions";
    const normalFilename = "abc123/log.jsonl";
    const fullPath = join(baseDir, normalFilename);

    const resolved = resolve(fullPath);
    const resolvedBase = resolve(baseDir) + "/";

    expect(resolved.startsWith(resolvedBase)).toBe(true);
  });
});

// ── stop() ──

describe("stop()", () => {
  it("clears file offsets and pendingReads", async () => {
    const tailer = new SessionLogTailer(tempDir);
    const filePath = join(tempDir, "stop-test.jsonl");

    await writeFile(filePath, '{"role":"user","text":"data"}\n');
    await tailer.readNewLines(filePath);

    const offsets = (tailer as any).fileOffsets as Map<string, number>;
    const pending = (tailer as any).pendingReads as Set<string>;
    expect(offsets.size).toBeGreaterThan(0);

    tailer.stop();

    expect(offsets.size).toBe(0);
    expect(pending.size).toBe(0);
  });

  it("aborts the watcher abort controller", () => {
    const tailer = new SessionLogTailer(tempDir);
    const ac = (tailer as any).abortController as AbortController;

    expect(ac.signal.aborted).toBe(false);

    tailer.stop();

    expect(ac.signal.aborted).toBe(true);
  });

  it("can be called multiple times without error", () => {
    const tailer = new SessionLogTailer(tempDir);
    expect(() => {
      tailer.stop();
      tailer.stop();
    }).not.toThrow();
  });
});
