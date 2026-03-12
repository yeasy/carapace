/**
 * @carapace/adapter-mcp — MCP 协议代理适配器
 *
 * 作为 MCP (Model Context Protocol) 透明代理运行，
 * 在 client 和实际 MCP server 之间拦截 tool call 请求，
 * 通过 Carapace 规则引擎进行安全检测。
 *
 * 用法:
 * ```typescript
 * import { createMcpProxy } from "@carapace/adapter-mcp";
 *
 * const proxy = createMcpProxy({
 *   blockOnCritical: true,
 *   debug: true,
 * });
 *
 * // 作为 stdio 代理
 * await proxy.startStdio(targetCommand, targetArgs);
 *
 * // 或拦截 JSON-RPC 消息
 * const result = await proxy.handleMessage(jsonRpcMessage);
 * ```
 */

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
  generateEventId,
  type CarapaceConfig,
  type RuleContext,
  type SecurityEvent,
} from "@carapace/core";

import { spawn, type ChildProcess } from "node:child_process";

// ── JSON-RPC 类型 ──

interface JsonRpcRequest {
  jsonrpc: "2.0";
  id?: string | number;
  method: string;
  params?: Record<string, unknown>;
}

interface JsonRpcResponse {
  jsonrpc: "2.0";
  id?: string | number;
  result?: unknown;
  error?: {
    code: number;
    message: string;
    data?: unknown;
  };
}

// ── MCP 特有类型 ──

interface McpToolCallParams {
  name: string;
  arguments?: Record<string, unknown>;
}

// ── 代理配置 ──

export interface McpProxyConfig extends CarapaceConfig {
  /** 自定义 YAML 规则文本 */
  yamlRules?: string;
  /** 日志输出目标（默认 stderr） */
  logTarget?: "stderr" | "none";
}

// ── 拦截结果 ──

export interface InterceptResult {
  allowed: boolean;
  events: SecurityEvent[];
  blockReason?: string;
  /** 如果 allowed=false，返回 JSON-RPC 错误响应 */
  errorResponse?: JsonRpcResponse;
}

// ── MCP 代理类 ──

export class McpProxy {
  private engine: RuleEngine;
  private alertRouter: AlertRouter;
  private config: McpProxyConfig;
  private childProcess: ChildProcess | null = null;
  private sessionId: string;
  private stats = {
    totalRequests: 0,
    toolCalls: 0,
    blocked: 0,
    alerts: 0,
  };

  constructor(config: McpProxyConfig = {}) {
    this.config = config;
    this.sessionId = `mcp-${Date.now()}`;
    this.engine = new RuleEngine();
    this.alertRouter = new AlertRouter();

    this.initEngine();
    this.initAlertRouter();
  }

  private initEngine(): void {
    // 注册内置规则
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

    if (this.config.trustedSkills?.length) {
      this.engine.setTrustedSkills(this.config.trustedSkills);
    }

    // 加载 YAML 自定义规则
    if (this.config.yamlRules) {
      const yamlRules = loadYamlRules(this.config.yamlRules);
      for (const rule of yamlRules) {
        this.engine.addRule(rule);
      }
    }
  }

  private initAlertRouter(): void {
    if (this.config.logTarget !== "none") {
      this.alertRouter.addSink(new ConsoleSink());
    }
    if (this.config.alertWebhook) {
      this.alertRouter.addSink(new WebhookSink(this.config.alertWebhook));
    }
    if (this.config.logFile) {
      this.alertRouter.addSink(new LogFileSink(this.config.logFile));
    }
  }

  private log(msg: string): void {
    if (this.config.debug && this.config.logTarget !== "none") {
      process.stderr.write(`[carapace-mcp] ${msg}\n`);
    }
  }

  /**
   * 拦截 JSON-RPC 消息。
   * 仅对 tools/call 方法进行安全检测，其他消息原样放行。
   */
  interceptRequest(request: JsonRpcRequest): InterceptResult {
    this.stats.totalRequests++;

    // 仅拦截 tools/call
    if (request.method !== "tools/call") {
      return { allowed: true, events: [] };
    }

    this.stats.toolCalls++;
    const toolParams = request.params as unknown as McpToolCallParams | undefined;
    const toolName = toolParams?.name ?? "unknown";
    const toolArgs = toolParams?.arguments ?? {};

    this.log(`拦截 tools/call: ${toolName}`);

    const ruleCtx: RuleContext = {
      toolName,
      toolParams: toolArgs,
      sessionId: this.sessionId,
      timestamp: Date.now(),
    };

    const { decision, events } = this.engine.evaluateForBlock(
      ruleCtx,
      this.config.blockOnCritical ?? false
    );

    // 发送告警
    if (events.length > 0) {
      this.stats.alerts += events.length;
      for (const evt of events) {
        this.alertRouter.send(evt).catch(() => {/* 告警发送失败不影响主流程 */});
      }
    }

    if (decision.block) {
      this.stats.blocked++;
      this.log(`已阻断: ${toolName} — ${decision.blockReason}`);

      return {
        allowed: false,
        events,
        blockReason: decision.blockReason,
        errorResponse: {
          jsonrpc: "2.0",
          id: request.id,
          error: {
            code: -32600,
            message: `🛡️ Carapace: ${decision.blockReason}`,
            data: {
              blocked: true,
              events: events.map((e) => ({
                category: e.category,
                severity: e.severity,
                title: e.title,
              })),
            },
          },
        },
      };
    }

    return { allowed: true, events };
  }

  /**
   * 拦截工具调用结果（after_tool_call 阶段）
   */
  interceptResponse(
    toolName: string,
    result: unknown
  ): SecurityEvent[] {
    if (!result || typeof result !== "string" || result.length < 50) {
      return [];
    }

    const resultCtx: RuleContext = {
      toolName,
      toolParams: { _result: result },
      sessionId: this.sessionId,
      timestamp: Date.now(),
    };

    const dataExfilRule = this.engine
      .getRules()
      .find((r) => r.name === "data-exfil");
    if (!dataExfilRule) return [];

    try {
      const check = dataExfilRule.check(resultCtx);
      if (check.triggered && check.event) {
        const fullEvent: SecurityEvent = {
          ...check.event,
          id: generateEventId(),
          timestamp: Date.now(),
          action: "alert",
          ruleName: "data-exfil",
          title: `[响应] ${check.event.title}`,
        };
        this.alertRouter.send(fullEvent).catch(() => {/* 不阻塞 */});
        return [fullEvent];
      }
    } catch {
      // 不影响主流程
    }
    return [];
  }

  /**
   * 以 stdio 代理模式启动：
   * stdin → Carapace → child.stdin
   * child.stdout → Carapace → stdout
   */
  async startStdio(
    command: string,
    args: string[] = [],
    options?: { env?: Record<string, string> }
  ): Promise<void> {
    this.log(`启动 stdio 代理: ${command} ${args.join(" ")}`);

    this.childProcess = spawn(command, args, {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, ...(options?.env ?? {}) },
    });

    const child = this.childProcess;

    // 读取 stdin（来自 LLM client）并拦截
    let stdinBuffer = "";

    // 处理 stdin EOF（client 断开连接时优雅关闭子进程）
    process.stdin.on("end", () => {
      this.log("stdin EOF，正在关闭子进程...");
      child.stdin?.end();
    });

    process.stdin.on("error", (err) => {
      this.log(`stdin 错误: ${err.message}`);
      child.stdin?.end();
    });

    process.stdin.on("data", (chunk: Buffer) => {
      stdinBuffer += chunk.toString();

      // JSON-RPC 消息以换行分隔
      const lines = stdinBuffer.split("\n");
      stdinBuffer = lines.pop() ?? "";

      for (const line of lines) {
        if (!line.trim()) {
          child.stdin?.write("\n");
          continue;
        }

        try {
          const request = JSON.parse(line) as JsonRpcRequest;
          const intercept = this.interceptRequest(request);

          if (!intercept.allowed && intercept.errorResponse) {
            // 阻断：直接返回错误给 client，不转发到 server
            process.stdout.write(
              JSON.stringify(intercept.errorResponse) + "\n"
            );
          } else {
            // 放行：转发到实际 MCP server
            child.stdin?.write(line + "\n");
          }
        } catch {
          // 非 JSON 行原样转发
          child.stdin?.write(line + "\n");
        }
      }
    });

    // 读取 child stdout（来自 MCP server）并转发到 stdout
    if (child.stdout) {
      child.stdout.on("data", (chunk: Buffer) => {
        process.stdout.write(chunk);
      });
      child.stdout.on("end", () => {
        this.log("子进程 stdout 已关闭");
      });
    }

    // child stderr → 我们的 stderr
    if (child.stderr) {
      child.stderr.on("data", (chunk: Buffer) => {
        process.stderr.write(chunk);
      });
    }

    // 等待子进程退出
    return new Promise((resolve, reject) => {
      child.on("close", (code) => {
        this.log(`子进程退出, code=${code}`);
        this.log(
          `统计: 总请求=${this.stats.totalRequests}, ` +
            `工具调用=${this.stats.toolCalls}, ` +
            `告警=${this.stats.alerts}, ` +
            `阻断=${this.stats.blocked}`
        );
        if (code === 0 || code === null) resolve();
        else reject(new Error(`MCP server exited with code ${code}`));
      });

      child.on("error", reject);
    });
  }

  /**
   * 停止代理
   */
  stop(): void {
    if (this.childProcess) {
      this.childProcess.kill("SIGTERM");
      this.childProcess = null;
    }
  }

  /**
   * 获取统计信息
   */
  getStats(): typeof this.stats {
    return { ...this.stats };
  }

  /**
   * 获取已加载的规则数
   */
  getRuleCount(): number {
    return this.engine.getRules().length;
  }
}

// ── 便捷工厂函数 ──

export function createMcpProxy(config?: McpProxyConfig): McpProxy {
  return new McpProxy(config);
}

export default McpProxy;
