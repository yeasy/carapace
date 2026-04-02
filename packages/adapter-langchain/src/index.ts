/**
 * @carapace/adapter-langchain — Python 框架桥接适配器
 *
 * 提供 HTTP server，让 Python 框架（LangChain、CrewAI、AutoGen）
 * 通过 HTTP 调用 Carapace 进行安全检测。
 *
 * 架构：
 * ┌──────────────────────┐     HTTP      ┌───────────────────┐
 * │  Python Agent 框架    │  ──────────→  │  Carapace Bridge   │
 * │  (LangChain/CrewAI)  │  ←──────────  │  (Node.js HTTP)    │
 * └──────────────────────┘    JSON       └───────────────────┘
 *
 * Python 端使用示例:
 * ```python
 * import requests
 *
 * # 在工具调用前检测
 * response = requests.post("http://localhost:9876/check", json={
 *     "toolName": "bash",
 *     "toolParams": {"command": "rm -rf /"},
 *     "sessionId": "my-session",
 *     "skillName": "data-agent",
 * })
 *
 * result = response.json()
 * if result["block"]:
 *     print(f"Blocked: {result['blockReason']}")
 * ```
 */

import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";

let PKG_VERSION = "unknown";
try {
  PKG_VERSION = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf-8")).version;
} catch { /* fallback to "unknown" */ }

import {
  RuleEngine,
  AlertRouter,
  ConsoleSink,
  WebhookSink,
  LogFileSink,
  execGuardRule,
  createPathGuardRule,
  createNetworkGuardRule,
  createRateLimiterRule,
  createPromptInjectionRule,
  createDataExfilRule,
  createBaselineDriftRule,
  loadYamlRules,
  type CarapaceConfig,
  type RuleContext,
  type SecurityRule,
} from "@carapace/core";

// ── 配置 ──

export interface BridgeConfig extends CarapaceConfig {
  /** HTTP 监听端口（默认 9876） */
  port?: number;
  /** 绑定地址（默认 127.0.0.1） */
  host?: string;
  /** YAML 自定义规则文本 */
  yamlRules?: string;
  /** CORS 允许的来源（默认不设置，仅同源可访问） */
  corsOrigin?: string;
  /** 请求体最大字节数（默认 1MB） */
  maxBodySize?: number;
}

// ── 请求/响应类型 ──

interface CheckRequest {
  toolName: string;
  toolParams: Record<string, unknown>;
  toolCallId?: string;
  sessionId?: string;
  agentId?: string;
  skillName?: string;
}

interface CheckResponse {
  block: boolean;
  blockReason?: string;
  events: Array<{
    category: string;
    severity: string;
    title: string;
    description: string;
    ruleName?: string;
  }>;
}

interface StatusResponse {
  status: "ok";
  version: string;
  rules: number;
  trustedSkills: string[];
  stats: {
    totalChecks: number;
    totalBlocked: number;
    totalAlerts: number;
  };
}

// ── Bridge Server ──

export class CarapaceBridge {
  private engine: RuleEngine;
  private alertRouter: AlertRouter;
  private config: BridgeConfig;
  private server: ReturnType<typeof createServer> | null = null;
  private stats = {
    totalChecks: 0,
    totalBlocked: 0,
    totalAlerts: 0,
  };

  constructor(config: BridgeConfig = {}) {
    this.config = config;
    this.engine = new RuleEngine();
    this.alertRouter = new AlertRouter();

    this.initEngine();
    this.initAlertRouter();
  }

  private initEngine(): void {
    this.engine.addRule(execGuardRule);
    this.engine.addRule(createPathGuardRule(this.config.sensitivePathPatterns));
    this.engine.addRule(createNetworkGuardRule(this.config.blockedDomains));
    this.engine.addRule(createPromptInjectionRule());
    this.engine.addRule(createDataExfilRule());

    if (this.config.maxToolCallsPerMinute) {
      this.engine.addRule(
        createRateLimiterRule(this.config.maxToolCallsPerMinute)
      );
    }

    if (this.config.enableBaseline) {
      const { rule } = createBaselineDriftRule();
      this.engine.addRule(rule);
    }

    if (Array.isArray(this.config.trustedSkills) && this.config.trustedSkills.length > 0) {
      this.engine.setTrustedSkills(this.config.trustedSkills);
    }

    if (this.config.yamlRules) {
      const yamlRules = loadYamlRules(this.config.yamlRules);
      for (const rule of yamlRules) {
        this.engine.addRule(rule);
      }
    }
  }

  private initAlertRouter(): void {
    this.alertRouter.addSink(new ConsoleSink());
    if (this.config.alertWebhook) {
      this.alertRouter.addSink(new WebhookSink(this.config.alertWebhook));
    }
    if (this.config.logFile) {
      this.alertRouter.addSink(new LogFileSink(this.config.logFile));
    }
  }

  private log(msg: string): void {
    if (this.config.debug) {
      process.stderr.write(`[carapace-bridge] ${msg}\n`);
    }
  }

  /**
   * 安全检测
   */
  check(req: CheckRequest): CheckResponse {
    this.stats.totalChecks++;

    const ruleCtx: RuleContext = {
      toolName: req.toolName,
      toolParams: req.toolParams,
      toolCallId: req.toolCallId,
      sessionId: req.sessionId,
      agentId: req.agentId,
      skillName: req.skillName,
      timestamp: Date.now(),
    };

    const { decision, events } = this.engine.evaluateForBlock(
      ruleCtx,
      this.config.blockOnCritical ?? false
    );

    if (events.length > 0) {
      this.stats.totalAlerts += events.length;
      for (const evt of events) {
        this.alertRouter.send(evt).catch((err) => { process.stderr.write(`[carapace-bridge] alert send failed: ${err}\n`); });
      }
    }

    if (decision.block) {
      this.stats.totalBlocked++;
    }

    return {
      block: decision.block,
      blockReason: decision.blockReason,
      events: events.map((e) => ({
        category: e.category,
        severity: e.severity,
        title: e.title,
        description: e.description,
        ruleName: e.ruleName,
      })),
    };
  }

  /**
   * 添加自定义规则
   */
  addRule(rule: SecurityRule): void {
    this.engine.addRule(rule);
  }

  /**
   * 获取状态信息
   */
  getStatus(): StatusResponse {
    return {
      status: "ok",
      version: PKG_VERSION,
      rules: this.engine.getRules().length,
      trustedSkills: [], // Redacted: trusted skill names are security-sensitive
      stats: { ...this.stats },
    };
  }

  /**
   * 启动 HTTP 服务
   */
  async start(): Promise<void> {
    if (this.server) throw new Error("Bridge already running — call stop() first");
    const port = this.config.port ?? 9876;
    const host = this.config.host ?? "127.0.0.1";
    const corsOrigin = this.config.corsOrigin;
    const maxBodySize = this.config.maxBodySize ?? 1_048_576; // 1 MB

    this.server = createServer((req: IncomingMessage, res: ServerResponse) => {
      // Security headers
      res.setHeader("X-Content-Type-Options", "nosniff");
      res.setHeader("X-Frame-Options", "DENY");

      // CORS headers only when explicitly configured
      if (corsOrigin) {
        res.setHeader("Access-Control-Allow-Origin", corsOrigin);
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", "Content-Type");
      }

      if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return;
      }

      const url = req.url ?? "/";
      const urlPath = url.split("?")[0];

      // GET /status
      if (req.method === "GET" && urlPath === "/status") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(this.getStatus()));
        return;
      }

      // GET /health
      if (req.method === "GET" && urlPath === "/health") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "ok" }));
        return;
      }

      // ── 限制请求体大小的辅助函数 ──
      const readBody = (req: IncomingMessage, cb: (body: string) => void): void => {
        const chunks: Buffer[] = [];
        let totalSize = 0;
        let exceeded = false;
        let responded = false;
        req.on("data", (chunk: Buffer) => {
          totalSize += chunk.length;
          if (totalSize > maxBodySize) {
            exceeded = true;
            req.destroy();
            return;
          }
          chunks.push(chunk);
        });
        const send413 = () => {
          if (responded) return;
          responded = true;
          res.writeHead(413, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: `Request body exceeds limit (${maxBodySize} bytes)` }));
        };
        req.on("end", () => {
          if (exceeded) { send413(); return; }
          try {
            const body = Buffer.concat(chunks).toString("utf-8");
            cb(body);
          } catch {
            if (!responded) {
              responded = true;
              res.writeHead(500, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: "Internal server error" }));
            }
          }
        });
        req.on("error", () => {
          if (exceeded) { send413(); return; }
          if (!responded) {
            responded = true;
            res.writeHead(500, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Request error" }));
          }
        });
      };

      // POST /check
      if (req.method === "POST" && urlPath === "/check") {
        readBody(req, (body) => {
          try {
            const checkReq = JSON.parse(body) as CheckRequest;

            if (!checkReq.toolName || typeof checkReq.toolName !== "string" || !checkReq.toolParams || checkReq.toolParams === null || typeof checkReq.toolParams !== "object" || Array.isArray(checkReq.toolParams)) {
              res.writeHead(400, { "Content-Type": "application/json" });
              res.end(
                JSON.stringify({
                  error: "Missing or invalid required fields: toolName (string), toolParams (object)",
                })
              );
              return;
            }

            const result = this.check(checkReq);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(result));
          } catch {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Invalid JSON body" }));
          }
        });
        return;
      }

      // POST /check/batch
      if (req.method === "POST" && urlPath === "/check/batch") {
        readBody(req, (body) => {
          try {
            const checks = JSON.parse(body) as CheckRequest[];
            if (!Array.isArray(checks)) {
              res.writeHead(400, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: "Expected array of check requests" }));
              return;
            }

            if (checks.length > 100) {
              res.writeHead(400, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: "Batch size exceeds maximum of 100 items" }));
              return;
            }

            // Validate each item has required fields
            for (let i = 0; i < checks.length; i++) {
              if (!checks[i] || typeof checks[i] !== "object" || !checks[i].toolName || !checks[i].toolParams || typeof checks[i].toolParams !== "object" || Array.isArray(checks[i].toolParams)) {
                res.writeHead(400, { "Content-Type": "application/json" });
                res.end(JSON.stringify({
                  error: `Item ${i}: missing required fields toolName, toolParams`,
                }));
                return;
              }
            }

            const results = checks.map((c) => this.check(c));
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(results));
          } catch {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "Invalid JSON body" }));
          }
        });
        return;
      }

      // 404
      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Not found" }));
    });

    // Set timeouts to prevent slow-loris style attacks
    this.server.requestTimeout = 30_000;
    this.server.headersTimeout = 10_000;
    this.server.keepAliveTimeout = 5_000;

    return new Promise((resolve, reject) => {
      const onError = (err: Error) => {
        const srv = this.server;
        this.server = null;
        srv?.close();
        reject(err);
      };
      this.server!.on("error", onError);
      this.server!.listen(port, host, () => {
        this.server!.removeListener("error", onError);
        this.server!.on("error", (err: Error) => {
          this.log(`HTTP server error: ${err.message}`);
        });
        this.log(`HTTP bridge 已启动: http://${host}:${port}`);
        this.log(
          `已加载 ${this.engine.getRules().length} 条规则, ` +
            `阻断=${this.config.blockOnCritical ? "开启" : "关闭"}`
        );
        resolve();
      });
    });
  }

  /**
   * 获取当前监听端口（服务器启动后可用，端口 0 时获取实际分配端口）
   */
  getPort(): number {
    if (this.server) {
      const addr = this.server.address();
      if (addr && typeof addr === "object") {
        return addr.port;
      }
    }
    return this.config.port ?? 9876;
  }

  /**
   * 停止 HTTP 服务
   */
  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          this.server = null;
          this.log("HTTP bridge 已停止");
          resolve();
        });
        // Force-close active keep-alive connections (Node.js 18.2+)
        this.server.closeAllConnections?.();
      } else {
        resolve();
      }
    });
  }
}

// ── Python 客户端示例代码（供文档使用） ──

export const PYTHON_CLIENT_EXAMPLE = `
"""
carapace_client.py — Carapace Python 客户端

用法:
    from carapace_client import CarapaceGuard

    guard = CarapaceGuard()

    # 在工具调用前检测
    result = guard.check("bash", {"command": "rm -rf /"})
    if result["block"]:
        raise RuntimeError(f"Blocked by Carapace: {result['blockReason']}")
    # 否则继续执行工具调用...
"""

import requests
from typing import Any


class CarapaceGuard:
    def __init__(self, base_url: str = "http://127.0.0.1:9876"):
        self.base_url = base_url.rstrip("/")

    def check(
        self,
        tool_name: str,
        tool_params: dict[str, Any],
        session_id: str | None = None,
        skill_name: str | None = None,
    ) -> dict:
        payload = {
            "toolName": tool_name,
            "toolParams": tool_params,
        }
        if session_id:
            payload["sessionId"] = session_id
        if skill_name:
            payload["skillName"] = skill_name

        resp = requests.post(f"{self.base_url}/check", json=payload, timeout=5)
        resp.raise_for_status()
        return resp.json()

    def check_batch(self, checks: list[dict]) -> list[dict]:
        resp = requests.post(
            f"{self.base_url}/check/batch", json=checks, timeout=10
        )
        resp.raise_for_status()
        return resp.json()

    def status(self) -> dict:
        resp = requests.get(f"{self.base_url}/status", timeout=5)
        resp.raise_for_status()
        return resp.json()

    def health(self) -> bool:
        try:
            resp = requests.get(f"{self.base_url}/health", timeout=2)
            return resp.status_code == 200
        except Exception:
            return False
`;

// ── 便捷工厂函数 ──

export function createBridge(config?: BridgeConfig): CarapaceBridge {
  return new CarapaceBridge(config);
}

export default CarapaceBridge;
