/**
 * @carapace/adapter-openclaw — OpenClaw 插件入口
 *
 * 作为 OpenClaw 原生插件运行，通过 hook 系统拦截工具调用，
 * 评估安全规则，可选地阻断危险操作并发送告警。
 *
 * 安装：openclaw plugins install @carapace/adapter-openclaw
 * 配置：~/.openclaw/config.json → plugins.entries.carapace.config
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
  type CarapaceConfig,
  type RuleContext,
} from "@carapace/core";

// ── OpenClaw 插件 API 类型（仅声明我们用到的部分） ──

interface OpenClawPluginApi {
  id: string;
  name: string;
  pluginConfig?: Record<string, unknown>;
  logger: {
    info(msg: string, ...args: unknown[]): void;
    warn(msg: string, ...args: unknown[]): void;
    error(msg: string, ...args: unknown[]): void;
    debug(msg: string, ...args: unknown[]): void;
  };
  on(
    hookName: string,
    handler: (event: any, ctx: any) => any,
    opts?: { priority?: number }
  ): void;
  registerCli?(registrar: any, opts?: { commands?: string[] }): void;
}

// ── 会话级计数器 ──

interface SessionStats {
  toolCalls: number;
  blockedCalls: number;
  alertsFired: number;
  startTime: number;
}

// ── 插件定义 ──

const plugin = {
  id: "carapace",
  name: "Carapace Security Monitor",
  description: "AI Agent 运行时安全监控：危险命令、敏感路径、可疑网络、Prompt 注入、数据外泄、行为基线。",

  register(api: OpenClawPluginApi) {
    const config = (api.pluginConfig ?? {}) as CarapaceConfig;
    const debug = config.debug ?? false;

    if (debug) api.logger.info("[carapace] 初始化中...");

    // ── 1. 构建规则引擎 ──
    const engine = new RuleEngine();
    engine.addRule(execGuardRule);
    engine.addRule(createPathGuardRule(config.sensitivePathPatterns));
    engine.addRule(createNetworkGuardRule(config.blockedDomains));
    engine.addRule(createPromptInjectionRule());
    engine.addRule(createDataExfilRule());

    if (config.maxToolCallsPerMinute) {
      engine.addRule(createRateLimiterRule(config.maxToolCallsPerMinute));
    }

    // 行为基线（可选）
    let baselineTracker: InstanceType<typeof import("@carapace/core").BaselineTracker> | null = null;
    if (config.enableBaseline) {
      const { rule, tracker } = createBaselineDriftRule();
      engine.addRule(rule);
      baselineTracker = tracker;
    }

    // 设置受信 skill 白名单
    if (config.trustedSkills?.length) {
      engine.setTrustedSkills(config.trustedSkills);
    }

    if (debug) {
      api.logger.info(
        `[carapace] 已加载 ${engine.getRules().length} 条规则` +
          (config.trustedSkills?.length
            ? `, ${config.trustedSkills.length} 个受信 skill`
            : "") +
          (baselineTracker ? ", 行为基线已启用" : "")
      );
    }

    // ── 2. 构建告警路由 ──
    const alertRouter = new AlertRouter();
    alertRouter.addSink(new ConsoleSink());

    if (config.alertWebhook) {
      alertRouter.addSink(new WebhookSink(config.alertWebhook));
    }
    if (config.logFile) {
      alertRouter.addSink(new LogFileSink(config.logFile));
    }

    // ── 会话计数器 ──
    const sessionStats = new Map<string, SessionStats>();

    // ── 3. 注册 before_tool_call hook（主拦截点） ──
    api.on(
      "before_tool_call",
      async (
        event: { toolName: string; params: Record<string, unknown>; toolCallId?: string; runId?: string; skillName?: string },
        ctx: { agentId?: string; sessionId?: string; sessionKey?: string; runId?: string }
      ) => {
        const sessionId = ctx.sessionId ?? ctx.sessionKey ?? "__default__";
        const ruleCtx: RuleContext = {
          toolName: event.toolName,
          toolParams: event.params,
          toolCallId: event.toolCallId,
          sessionId,
          agentId: ctx.agentId,
          skillName: event.skillName,
          timestamp: Date.now(),
        };

        const { decision, events } = engine.evaluateForBlock(
          ruleCtx,
          config.blockOnCritical ?? false
        );

        // 更新会话计数器
        const stats = sessionStats.get(sessionId);
        if (stats) {
          stats.toolCalls++;
          if (events.length > 0) stats.alertsFired += events.length;
          if (decision.block) stats.blockedCalls++;
        }

        // 发送所有触发的事件到告警渠道
        for (const evt of events) {
          alertRouter.send(evt); // 不 await，不阻塞工具调用
        }

        if (decision.block) {
          if (debug) {
            api.logger.warn(
              `[carapace] 已阻断: ${event.toolName} — ${decision.blockReason}`
            );
          }
          return {
            block: true,
            blockReason: `🛡️ Carapace: ${decision.blockReason}`,
          };
        }

        return {};
      },
      { priority: 100 } // 高优先级，在其他 hook 之前运行
    );

    // ── 4. 注册 after_tool_call hook（结果观测） ──
    api.on(
      "after_tool_call",
      async (
        event: {
          toolName: string;
          params: Record<string, unknown>;
          result?: unknown;
          error?: string;
          durationMs?: number;
          skillName?: string;
        },
        _ctx: { agentId?: string; sessionId?: string }
      ) => {
        if (debug) {
          api.logger.debug(
            `[carapace] 工具完成: ${event.toolName} (${event.durationMs ?? "?"}ms)${event.error ? " ERROR" : ""}`
          );
        }

        // 检测响应中的数据外泄模式（当结果是字符串时）
        if (event.result && typeof event.result === "string" && event.result.length > 50) {
          const resultCtx: RuleContext = {
            toolName: event.toolName,
            toolParams: { _result: event.result },
            sessionId: _ctx.sessionId,
            agentId: _ctx.agentId,
            skillName: event.skillName,
            timestamp: Date.now(),
          };
          // 仅对结果运行 data-exfil 规则
          const dataExfilRule = engine.getRules().find((r) => r.name === "data-exfil");
          if (dataExfilRule) {
            try {
              const check = dataExfilRule.check(resultCtx);
              if (check.triggered && check.event) {
                const fullEvent = {
                  ...check.event,
                  id: "",
                  timestamp: Date.now(),
                  action: "alert" as const,
                  ruleName: "data-exfil",
                  title: `[响应] ${check.event.title}`,
                };
                alertRouter.send(fullEvent);
              }
            } catch {
              // 响应检测不应影响主流程
            }
          }
        }
      },
      { priority: 50 }
    );

    // ── 5. 注册 session_start / session_end ──
    api.on("session_start", async (_event: unknown, ctx: { sessionId?: string }) => {
      const sessionId = ctx.sessionId ?? "__default__";
      if (debug) {
        api.logger.info(`[carapace] 会话开始: ${sessionId}`);
      }
      // 初始化会话级计数器
      sessionStats.set(sessionId, {
        toolCalls: 0,
        blockedCalls: 0,
        alertsFired: 0,
        startTime: Date.now(),
      });
    });

    api.on("session_end", async (_event: unknown, ctx: { sessionId?: string }) => {
      const sessionId = ctx.sessionId ?? "__default__";
      const stats = sessionStats.get(sessionId);

      if (debug || (stats && stats.alertsFired > 0)) {
        const duration = stats ? Math.round((Date.now() - stats.startTime) / 1000) : 0;
        api.logger.info(
          `[carapace] 会话结束: ${sessionId} | ` +
            `工具调用: ${stats?.toolCalls ?? 0}, ` +
            `告警: ${stats?.alertsFired ?? 0}, ` +
            `阻断: ${stats?.blockedCalls ?? 0}, ` +
            `时长: ${duration}s` +
            (baselineTracker
              ? `, 基线 skill 数: ${baselineTracker.profileCount}`
              : "")
        );
      }

      // 清理会话数据
      sessionStats.delete(sessionId);
    });

    // ── 6. 注册 gateway_start（启动审计） ──
    api.on("gateway_start", async () => {
      const ruleCount = engine.getRules().length;
      api.logger.info(
        `[carapace] 🛡️ Carapace Security Monitor v0.3.0 已启动 (${ruleCount} 条规则, ` +
          `阻断=${config.blockOnCritical ? "开启" : "关闭"}` +
          (baselineTracker ? ", 基线=开启" : "") + ")"
      );
    });

    if (debug) api.logger.info("[carapace] 初始化完成");
  },
};

export default plugin;
