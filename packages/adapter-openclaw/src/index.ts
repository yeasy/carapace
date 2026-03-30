/**
 * @carapace/adapter-openclaw — OpenClaw 插件入口
 *
 * 作为 OpenClaw 原生插件运行，通过 hook 系统拦截工具调用，
 * 评估安全规则，可选地阻断危险操作并发送告警。
 *
 * 安装：openclaw plugins install @carapace/adapter-openclaw
 * 配置：~/.openclaw/config.json → plugins.entries.carapace.config
 */

import { readFileSync } from "node:fs";

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
  generateEventId,
  type CarapaceConfig,
  type RuleContext,
  type BaselineTracker,
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
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  on(hookName: string, handler: (...args: any[]) => any, opts?: { priority?: number }): void;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  registerCli?(registrar: any, opts?: { commands?: string[] }): void;
}

// ── 会话级计数器 ──

interface FirstRunReport {
  skillName: string;
  sessionId: string;
  startedAt: number;
  toolsUsed: Set<string>;
  filesAccessed: Set<string>;
  domainsContacted: Set<string>;
  commandsExecuted: string[];
  eventCount: number;
}

interface SessionStats {
  toolCalls: number;
  blockedCalls: number;
  alertsFired: number;
  startTime: number;
  lastActivity: number;
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
    let baselineTracker: BaselineTracker | null = null;
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
    const firstRunData = new Map<string, FirstRunReport>();

    // ── TTL 清理：每 5 分钟清理超过 1 小时未活动的会话数据 ──
    const SESSION_TTL_MS = 60 * 60 * 1000; // 1 小时
    const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 分钟
    const FIRST_RUN_DATA_MAX = 10_000; // cap on unique skills tracked
    const cleanupTimer = setInterval(() => {
      const now = Date.now();
      // Collect expired keys first, then delete (avoid mutating Map during iteration)
      const expiredSessions: string[] = [];
      for (const [sessionId, stats] of sessionStats) {
        if (now - stats.lastActivity > SESSION_TTL_MS) {
          if (debug) {
            api.logger.info(`[carapace] TTL 清理过期会话: ${sessionId}`);
          }
          expiredSessions.push(sessionId);
        }
      }
      for (const id of expiredSessions) sessionStats.delete(id);
      // Clean up stale firstRunData entries to prevent unbounded growth
      const expiredKeys: string[] = [];
      for (const [key, report] of firstRunData) {
        if (now - report.startedAt > SESSION_TTL_MS) {
          expiredKeys.push(key);
        }
      }
      for (const key of expiredKeys) firstRunData.delete(key);
    }, CLEANUP_INTERVAL_MS);
    // 避免 timer 阻止进程退出
    if (cleanupTimer.unref) cleanupTimer.unref();

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

        // 更新会话计数器（初始化如果 session_start 未触发）
        if (!sessionStats.has(sessionId)) {
          const now = Date.now();
          sessionStats.set(sessionId, {
            toolCalls: 0, blockedCalls: 0, alertsFired: 0,
            startTime: now, lastActivity: now,
          });
        }
        const stats = sessionStats.get(sessionId)!;
        stats.toolCalls++;
        stats.lastActivity = Date.now();
        if (events.length > 0) stats.alertsFired += events.length;
        if (decision.block) stats.blockedCalls++;

        // 更新首次运行报告的事件计数
        if (events.length > 0 && event.skillName) {
          const compositeKey = `${event.skillName}:${sessionId}`;
          const report = firstRunData.get(compositeKey);
          if (report) report.eventCount += events.length;
        }

        // 发送所有触发的事件到告警渠道
        for (const evt of events) {
          alertRouter.send(evt).catch((err: unknown) => { process.stderr.write(`[carapace-openclaw] alert send failed: ${err}\n`); });
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
          // 仅对结果运行 data-exfil 规则（受信 skill 跳过）
          const dataExfilRule = engine.getRules().find((r) => r.name === "data-exfil");
          if (dataExfilRule && !(event.skillName && engine.getTrustedSkills().has(event.skillName.trim().toLowerCase()))) {
            try {
              const check = dataExfilRule.check(resultCtx);
              if (check.triggered && check.event) {
                const fullEvent = {
                  ...check.event,
                  id: generateEventId(),
                  timestamp: Date.now(),
                  action: "alert" as const,
                  ruleName: "data-exfil",
                  title: `[响应] ${check.event.title}`,
                };
                alertRouter.send(fullEvent).catch((err: unknown) => { process.stderr.write(`[carapace-openclaw] alert send failed: ${err}\n`); });
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
      // Initialize session stats only if not already created by an earlier before_tool_call
      if (!sessionStats.has(sessionId)) {
        const now = Date.now();
        sessionStats.set(sessionId, {
          toolCalls: 0,
          blockedCalls: 0,
          alertsFired: 0,
          startTime: now,
          lastActivity: now,
        });
      }
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
        `[carapace] 🛡️ Carapace Security Monitor v${PKG_VERSION} 已启动 (${ruleCount} 条规则, ` +
          `阻断=${config.blockOnCritical ? "开启" : "关闭"}` +
          (baselineTracker ? ", 基线=开启" : "") + ")"
      );
    });

    // ── 7. 注册 gateway_stop（优雅关闭） ──
    api.on("gateway_stop", async () => {
      // 打印所有活跃会话的摘要
      if (sessionStats.size > 0) {
        api.logger.info(`[carapace] 关闭中... 刷新 ${sessionStats.size} 个活跃会话的统计数据`);
        for (const [sessionId, stats] of sessionStats) {
          if (stats.alertsFired > 0 || debug) {
            const duration = Math.round((Date.now() - stats.startTime) / 1000);
            api.logger.info(
              `[carapace] 会话 ${sessionId}: ` +
                `工具调用=${stats.toolCalls}, 告警=${stats.alertsFired}, ` +
                `阻断=${stats.blockedCalls}, 时长=${duration}s`
            );
          }
        }
      }
      // 清理资源
      sessionStats.clear();
      clearInterval(cleanupTimer);
      api.logger.info("[carapace] 🛡️ Carapace 已关闭");
    });

    // ── 8. 首次运行报告生成器 ──
    // 追踪每个 skill 的首次会话，记录其所有工具调用、路径和域名

    api.on(
      "after_tool_call",
      async (
        event: {
          toolName: string;
          params: Record<string, unknown>;
          result?: unknown;
          skillName?: string;
        },
        ctx: { sessionId?: string }
      ) => {
        const skillName = event.skillName;
        if (!skillName) return;

        // 仅在基线启用且该 skill 处于学习阶段时收集首次运行数据
        if (!baselineTracker || !baselineTracker.isLearning(skillName)) {
          return; // 基线未启用或已学习完成，不再收集
        }

        const sessionId = ctx.sessionId ?? "__default__";
        const compositeKey = `${skillName}:${sessionId}`;

        if (!firstRunData.has(compositeKey)) {
          // Evict oldest entries when cap is reached
          if (firstRunData.size >= FIRST_RUN_DATA_MAX) {
            let oldestKey: string | undefined;
            let oldestTime = Infinity;
            for (const [key, val] of firstRunData) {
              if (val.startedAt < oldestTime) {
                oldestTime = val.startedAt;
                oldestKey = key;
              }
            }
            if (oldestKey) firstRunData.delete(oldestKey);
          }
          firstRunData.set(compositeKey, {
            skillName,
            sessionId,
            startedAt: Date.now(),
            toolsUsed: new Set<string>(),
            filesAccessed: new Set<string>(),
            domainsContacted: new Set<string>(),
            commandsExecuted: [],
            eventCount: 0,
          });
        }

        const report = firstRunData.get(compositeKey)!;
        if (report.toolsUsed.size < 500) report.toolsUsed.add(event.toolName);

        // 提取文件路径
        const params = event.params;
        const pathLike = params.path ?? params.file ?? params.filePath ?? params.filename;
        if (typeof pathLike === "string") {
          if (report.filesAccessed.size < 500) report.filesAccessed.add(pathLike);
        }

        // 提取域名
        const urlLike = params.url ?? params.domain ?? params.host;
        if (typeof urlLike === "string") {
          try {
            const url = new URL(urlLike.startsWith("http") ? urlLike : `https://${urlLike}`);
            if (report.domainsContacted.size < 200) report.domainsContacted.add(url.hostname);
          } catch {
            // 非 URL 格式，忽略
          }
        }

        // 提取命令
        const cmdLike = params.command ?? params.cmd;
        if (typeof cmdLike === "string" && report.commandsExecuted.length < 1000) {
          report.commandsExecuted.push(cmdLike.length > 1024 ? cmdLike.slice(0, 1024) : cmdLike);
        }
      },
      { priority: 10 } // 低优先级，在安全检查之后
    );

    // 会话结束时输出首次运行报告
    api.on("session_end", async (_event: unknown, ctx: { sessionId?: string }) => {
      const sessionId = ctx.sessionId ?? "__default__";

      // Collect keys to delete before iterating to avoid modifying Map during iteration
      const keysToDelete: string[] = [];
      for (const [compositeKey, report] of firstRunData) {
        if (report.sessionId !== sessionId) continue;

        // 生成首次运行报告
        const duration = Math.round((Date.now() - report.startedAt) / 1000);
        api.logger.info(
          `\n${"─".repeat(60)}\n` +
            `[carapace] 📋 首次运行报告: ${report.skillName}\n` +
            `${"─".repeat(60)}\n` +
            `  会话: ${sessionId}\n` +
            `  时长: ${duration}s\n` +
            `  工具使用: ${[...report.toolsUsed].join(", ") || "无"}\n` +
            `  文件访问: ${[...report.filesAccessed].join(", ") || "无"}\n` +
            `  网络域名: ${[...report.domainsContacted].join(", ") || "无"}\n` +
            `  命令执行: ${report.commandsExecuted.length > 0 ? "\n    " + report.commandsExecuted.join("\n    ") : "无"}\n` +
            `  安全事件: ${report.eventCount}\n` +
            `${"─".repeat(60)}\n`
        );

        keysToDelete.push(compositeKey);
      }
      for (const key of keysToDelete) firstRunData.delete(key);
    });

    if (debug) api.logger.info("[carapace] 初始化完成");
  },
};

export default plugin;
