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

// ── 插件定义 ──

const plugin = {
  id: "carapace",
  name: "Carapace Security Monitor",
  description: "AI Agent 运行时安全监控：危险命令检测、敏感路径防护、可疑网络告警。",

  register(api: OpenClawPluginApi) {
    const config = (api.pluginConfig ?? {}) as CarapaceConfig;
    const debug = config.debug ?? false;

    if (debug) api.logger.info("[carapace] 初始化中...");

    // ── 1. 构建规则引擎 ──
    const engine = new RuleEngine();
    engine.addRule(execGuardRule);
    engine.addRule(createPathGuardRule(config.sensitivePathPatterns));
    engine.addRule(createNetworkGuardRule(config.blockedDomains));

    if (debug) {
      api.logger.info(
        `[carapace] 已加载 ${engine.getRules().length} 条规则`
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

    // ── 3. 注册 before_tool_call hook（主拦截点） ──
    api.on(
      "before_tool_call",
      async (
        event: { toolName: string; params: Record<string, unknown>; toolCallId?: string; runId?: string },
        ctx: { agentId?: string; sessionId?: string; sessionKey?: string; runId?: string }
      ) => {
        const ruleCtx: RuleContext = {
          toolName: event.toolName,
          toolParams: event.params,
          toolCallId: event.toolCallId,
          sessionId: ctx.sessionId ?? ctx.sessionKey,
          agentId: ctx.agentId,
          timestamp: Date.now(),
        };

        const { decision, events } = engine.evaluateForBlock(
          ruleCtx,
          config.blockOnCritical ?? false
        );

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
        },
        ctx: { agentId?: string; sessionId?: string }
      ) => {
        if (debug) {
          api.logger.debug(
            `[carapace] 工具完成: ${event.toolName} (${event.durationMs ?? "?"}ms)${event.error ? " ERROR" : ""}`
          );
        }
        // TODO v0.2: 将结果供给基线建模器
        // TODO v0.2: 检测响应中的数据外泄模式
      },
      { priority: 50 }
    );

    // ── 5. 注册 session_start / session_end ──
    api.on("session_start", async (_event: unknown, ctx: { sessionId?: string }) => {
      if (debug) {
        api.logger.info(`[carapace] 会话开始: ${ctx.sessionId ?? "unknown"}`);
      }
      // TODO v0.2: 初始化会话级计数器
    });

    api.on("session_end", async (_event: unknown, ctx: { sessionId?: string }) => {
      if (debug) {
        api.logger.info(`[carapace] 会话结束: ${ctx.sessionId ?? "unknown"}`);
      }
      // TODO v0.2: 生成会话摘要报告，更新 skill 基线
    });

    // ── 6. 注册 gateway_start（启动审计） ──
    api.on("gateway_start", async () => {
      const ruleCount = engine.getRules().length;
      api.logger.info(
        `[carapace] 🛡️ Carapace Security Monitor v0.1.0 已启动 (${ruleCount} 条规则, ` +
          `阻断=${config.blockOnCritical ? "开启" : "关闭"})`
      );
    });

    if (debug) api.logger.info("[carapace] 初始化完成");
  },
};

export default plugin;
