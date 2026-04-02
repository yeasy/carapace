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
import { StringDecoder } from "node:string_decoder";

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
  private stdinListeners: { event: string; handler: (...args: unknown[]) => void }[] = [];
  private sessionId: string;
  private stats = {
    totalRequests: 0,
    toolCalls: 0,
    blocked: 0,
    alerts: 0,
  };

  constructor(config: McpProxyConfig = {}) {
    this.config = config;
    this.sessionId = `mcp-${crypto.randomUUID()}`;
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

    if (Array.isArray(this.config.trustedSkills) && this.config.trustedSkills.length > 0) {
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
    if (typeof request.method !== "string") {
      return {
        allowed: false,
        events: [],
        errorResponse: {
          jsonrpc: "2.0",
          id: request.id ?? undefined,
          error: { code: -32600, message: "Invalid request: method must be a string" },
        },
      };
    }

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
        this.alertRouter.send(evt).catch((err) => { process.stderr.write(`[carapace-mcp] alert send failed: ${err}\n`); });
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
            code: -32001,
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
    result: unknown,
    skillName?: string
  ): SecurityEvent[] {
    if (!result || typeof result !== "string" || result.length < 50) {
      return [];
    }

    // 受信 skill 跳过规则评估（normalized to match engine behavior）
    if (skillName && this.engine.getTrustedSkills().has(skillName.trim().toLowerCase())) {
      return [];
    }

    const resultCtx: RuleContext = {
      toolName,
      toolParams: { _result: result },
      sessionId: this.sessionId,
      skillName,
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
        this.alertRouter.send(fullEvent).catch((err) => { process.stderr.write(`[carapace-mcp] alert send failed: ${err}\n`); });
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
    // Validate command to prevent command injection
    if (/[\x00\n\r|;&`$(){}]/.test(command) || command.includes("..")) {
      throw new Error(`McpProxy: unsafe command rejected: contains shell metacharacters or path traversal`);
    }
    for (const arg of args) {
      if (/\x00/.test(arg)) {
        throw new Error(`McpProxy: unsafe argument rejected: contains null byte`);
      }
    }

    // Sanitize log output to prevent terminal escape sequence injection
    const sanitize = (s: string) => s.replace(/[\x00-\x1f\x7f]/g, "");
    this.log(`启动 stdio 代理: ${sanitize(command)} ${args.map(sanitize).join(" ")}`);

    // Sanitize env overrides: block security-sensitive variables that could
    // enable code injection in child processes (e.g., LD_PRELOAD, NODE_OPTIONS)
    const BLOCKED_ENV_KEYS = new Set([
      "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
      "NODE_OPTIONS", "NODE_DEBUG", "ELECTRON_RUN_AS_NODE",
      "BASH_ENV", "ENV", "ZDOTDIR",
      "PYTHONSTARTUP", "PYTHONPATH",
      "PERL5OPT", "PERL5LIB",
      "RUBYOPT", "RUBYLIB",
      "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS",  // Java agent injection
      "GCONV_PATH", "GETCONF_DIR",           // glibc code execution
      "HOSTALIASES",                          // DNS resolution override
      "DOTNET_STARTUP_HOOKS",                 // .NET code injection
      "GOFLAGS",                              // Go build flag injection
    ]);
    const safeEnv: Record<string, string> = {};
    for (const [k, v] of Object.entries(options?.env ?? {})) {
      if (!BLOCKED_ENV_KEYS.has(k.toUpperCase())) {
        safeEnv[k] = v;
      }
    }

    this.childProcess = spawn(command, args, {
      stdio: ["pipe", "pipe", "pipe"],
      env: { ...process.env, ...safeEnv },
    });

    const child = this.childProcess;

    // 读取 stdin（来自 LLM client）并拦截
    let stdinBuffer = "";
    const stdinDecoder = new StringDecoder("utf-8"); // handle multi-byte char boundaries
    const MAX_STDIN_BUFFER = 10 * 1024 * 1024; // 10MB 上限，防止内存耗尽

    // 处理 stdin EOF（client 断开连接时优雅关闭子进程）
    const onEnd = () => {
      this.log("stdin EOF，正在关闭子进程...");
      stdinBuffer += stdinDecoder.end();
      // Flush any remaining complete message in the buffer before closing
      if (stdinBuffer.trim()) {
        try {
          const request = JSON.parse(stdinBuffer) as JsonRpcRequest;
          const intercept = this.interceptRequest(request);
          if (!intercept.allowed && intercept.errorResponse) {
            process.stdout.write(JSON.stringify(intercept.errorResponse) + "\n");
          } else {
            if (child.stdin?.writable) { child.stdin.write(stdinBuffer + "\n"); }
          }
        } catch {
          // Non-JSON remainder on EOF — drop it to prevent forwarding unvalidated data.
          // An attacker could craft a partial JSON line followed by EOF to inject
          // arbitrary content into the child process stdin without security checks.
          this.log("dropping non-JSON remainder on stdin EOF");
        }
        stdinBuffer = "";
      }
      child.stdin?.end();
    };
    const onError = (err: Error) => {
      this.log(`stdin 错误: ${err.message}`);
      child.stdin?.end();
    };
    const onData = (chunk: Buffer) => {
      stdinBuffer += stdinDecoder.write(chunk);

      // 防止缓冲区无限增长导致内存耗尽
      if (stdinBuffer.length > MAX_STDIN_BUFFER) {
        this.log(`stdin 缓冲区超过 ${MAX_STDIN_BUFFER} 字节限制，断开连接`);
        // Clear buffer before removing listeners to prevent stale data processing in onEnd
        stdinBuffer = "";
        // Remove stdin listeners before killing to prevent further callbacks
        for (const { event, handler } of this.stdinListeners) {
          process.stdin.removeListener(event, handler);
        }
        this.stdinListeners = [];
        child.stdin?.end();
        child.kill("SIGTERM");
        return;
      }

      // JSON-RPC 消息以换行分隔（兼容 \r\n 和 \n）
      const lines = stdinBuffer.split(/\r?\n/);
      stdinBuffer = lines.pop() ?? "";

      for (const line of lines) {
        if (!line.trim()) {
          if (child.stdin?.writable) { child.stdin.write("\n"); }
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
            if (child.stdin?.writable) { child.stdin.write(line + "\n"); }
          }
        } catch {
          // Drop non-JSON lines — do not forward unvalidated content to child process
          this.log(`dropping non-JSON stdin line (${line.length} bytes)`);
        }
      }
    };

    process.stdin.on("end", onEnd);
    process.stdin.on("error", onError as (...args: unknown[]) => void);
    process.stdin.on("data", onData as (...args: unknown[]) => void);
    this.stdinListeners = [
      { event: "end", handler: onEnd },
      { event: "error", handler: onError as (...args: unknown[]) => void },
      { event: "data", handler: onData as (...args: unknown[]) => void },
    ];

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
      let settled = false;
      child.on("close", (code) => {
        if (settled) return;
        settled = true;
        // Clean up stdin listeners on normal exit to prevent leaks
        for (const { event, handler } of this.stdinListeners) {
          process.stdin.removeListener(event, handler);
        }
        this.stdinListeners = [];
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

      child.on("error", (err) => {
        if (settled) return;
        settled = true;
        // Clean up stdin listeners on spawn error to prevent leaks
        for (const { event, handler } of this.stdinListeners) {
          process.stdin.removeListener(event, handler);
        }
        this.stdinListeners = [];
        reject(err);
      });
    });
  }

  /**
   * 停止代理
   */
  stop(): void {
    // Remove stdin listeners to prevent leaks on restart
    for (const { event, handler } of this.stdinListeners) {
      process.stdin.removeListener(event, handler);
    }
    this.stdinListeners = [];

    if (this.childProcess) {
      const cp = this.childProcess;
      let exited = false;
      cp.once("close", () => { exited = true; });
      cp.kill("SIGTERM");
      // Escalate to SIGKILL if child doesn't exit within 5 seconds
      const killTimer = setTimeout(() => {
        if (!exited) {
          try { cp.kill("SIGKILL"); } catch { /* ignore */ }
        }
      }, 5000);
      cp.once("close", () => clearTimeout(killTimer));
      killTimer.unref();
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
