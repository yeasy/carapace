/**
 * ExecGuard — 危险 shell 命令检测
 *
 * 检测 exec/bash/shell 类工具中的危险命令模式：
 * 远程代码执行、反弹 shell、凭证窃取、编码混淆、破坏性操作。
 */

import { SEVERITY_RANK } from "../types.js";
import type { SecurityRule, RuleContext, RuleResult, Severity } from "../types.js";
import { redactSensitiveValues } from "../utils/redact.js";

interface DangerPattern {
  pattern: RegExp;
  severity: Severity;
  title: string;
  description: string;
}

const DANGER_PATTERNS: DangerPattern[] = [
  // ── 远程代码执行 ──
  {
    pattern: /(?:\/[\w.+-]+\/)*curl\s.*\|.*\b(sh|bash|zsh|dash|ksh|fish|python[23]?|ruby|node|perl)\b/i,
    severity: "critical",
    title: "远程代码执行：curl 管道到 shell",
    description: "下载并立即执行远程代码，这是恶意软件安装的头号向量。",
  },
  {
    pattern: /(?:\/[\w.+-]+\/)*wget\s.*\|.*\b(sh|bash|zsh|dash|ksh|fish|python[23]?|ruby|node|perl)\b/i,
    severity: "critical",
    title: "远程代码执行：wget 管道到 shell",
    description: "通过 wget 下载并立即执行远程代码。",
  },

  // ── 进程替换执行 ──
  {
    pattern: /\b(bash|sh|zsh)\s+<\(\s*(curl|wget)\s/i,
    severity: "critical",
    title: "远程代码执行：进程替换",
    description: "通过进程替换下载并执行远程代码——绕过管道检测的常见手法。",
  },

  // ── 编码混淆执行 ──
  {
    pattern: /base64\s+(-[dD]|--decode)\s*\|\s*(sh|bash|eval)/i,
    severity: "critical",
    title: "编码载荷执行",
    description: "解码并执行 base64 编码命令——常见恶意软件混淆技术。",
  },
  {
    pattern: /echo\s.*\|\s*base64\s+(-[dD]|--decode)\s*\|\s*(sh|bash)/i,
    severity: "critical",
    title: "混淆命令执行",
    description: "echo 编码数据 → 解码 → 执行，经典代码注入模式。",
  },

  // ── eval 动态执行 ──
  {
    pattern: /\beval\s*\$\(/i,
    severity: "high",
    title: "动态 eval 执行",
    description: "eval 配合命令替换——可从动态源执行任意代码。",
  },
  {
    pattern: /\beval\s+["'$]/i,
    severity: "high",
    title: "eval 字符串执行",
    description: "eval 直接执行字符串变量——可能执行注入的代码。",
  },
  {
    pattern: /\beval\s*`/i,
    severity: "high",
    title: "eval 反引号命令替换",
    description: "eval 配合反引号命令替换——可从动态源执行任意代码。",
  },

  // ── 命令替换执行 ──
  {
    pattern: /\b(bash|sh|zsh)\s+-c\s+["']\$\(\s*(curl|wget)\b/i,
    severity: "critical",
    title: "命令替换远程执行",
    description: "通过命令替换下载并执行远程代码。",
  },
  {
    pattern: /\bsource\s+<\(\s*(curl|wget)\b/i,
    severity: "critical",
    title: "进程替换 source 执行",
    description: "通过 source + 进程替换下载并执行远程代码。",
  },
  {
    pattern: /\.\s+<\(\s*(curl|wget)\b/i,
    severity: "critical",
    title: "dot-source 进程替换执行",
    description: "通过 . (dot) + 进程替换下载并执行远程代码。",
  },
  {
    pattern: /\bxargs\s+.*\b(sh|bash|zsh)\b/i,
    severity: "high",
    title: "xargs shell 执行",
    description: "通过 xargs 传递数据到 shell 执行。",
  },

  // ── heredoc/herestring 注入 ──
  {
    pattern: /\b(bash|sh|zsh)\s+<<<\s*.*\b(curl|wget|nc|ncat)\b/i,
    severity: "critical",
    title: "heredoc 注入执行",
    description: "通过 here-string 向 shell 注入包含网络工具的命令。",
  },

  // ── 凭证窃取 ──
  {
    pattern: /\b(cat|head|tail|less|more|strings|tac|nl)\s+.*~?\/?\.ssh\/(id_rsa|id_ed25519|id_ecdsa|authorized_keys)/i,
    severity: "critical",
    title: "SSH 密钥访问",
    description: "尝试读取 SSH 私钥——潜在凭证窃取。",
  },
  {
    pattern: /\b(cat|head|tail|less|more|strings|tac|nl)\s+.*~?\/?\.aws\/(credentials|config)/i,
    severity: "critical",
    title: "AWS 凭证访问",
    description: "尝试读取 AWS 凭证——潜在云账户接管。",
  },
  {
    pattern: /\b(cat|head|tail|less|more|strings|tac|nl)\b.*\.(pem|key|p12|pfx|jks)\b/i,
    severity: "high",
    title: "私钥文件访问",
    description: "尝试读取私钥或证书文件。",
  },
  {
    pattern: /\b(cat|head|tail|less|more|strings|tac|nl|grep|sed|awk|xxd|base64)\b.*~?\/?\.config\/gcloud\//i,
    severity: "critical",
    title: "GCP 凭证读取",
    description: "读取 Google Cloud 凭证文件。",
  },
  {
    pattern: /\b(cat|head|tail|less|more|strings|tac|nl|grep|sed|awk|xxd|base64)\b.*~?\/?\.kube\/config/i,
    severity: "high",
    title: "Kubernetes 配置读取",
    description: "读取 kubeconfig 文件——可能含嵌入凭证。",
  },
  {
    pattern: /\b(cat|head|tail|less|more|strings|tac|nl|grep|sed|awk|xxd|base64)\b.*~?\/?\.docker\/config\.json/i,
    severity: "high",
    title: "Docker 凭证读取",
    description: "读取 Docker 仓库认证凭证。",
  },
  {
    pattern: /\b(cat|head|tail|less|more|strings|tac|nl|grep|sed|awk|xxd|base64)\b.*~?\/?\.netrc/i,
    severity: "critical",
    title: ".netrc 凭证读取",
    description: "读取 .netrc 文件——包含明文网络凭证。",
  },

  // ── 凭证文件复制/传输 ──
  {
    pattern: /\b(cp|scp|rsync)\s+.*~?\/?\.ssh\/(id_rsa|id_ed25519|id_ecdsa|authorized_keys)/i,
    severity: "critical",
    title: "SSH 密钥复制/传输",
    description: "尝试复制或传输 SSH 私钥——潜在凭证外泄。",
  },
  {
    pattern: /\b(cp|scp|rsync)\s+.*~?\/?\.aws\/(credentials|config)/i,
    severity: "critical",
    title: "AWS 凭证复制/传输",
    description: "尝试复制或传输 AWS 凭证——潜在云账户接管。",
  },

  // ── 替代凭证读取手段 ──
  {
    pattern: /\bdd\s+if=.*~?\/?\.ssh\//i,
    severity: "critical",
    title: "dd 读取 SSH 密钥",
    description: "通过 dd 读取 SSH 密钥文件——绕过常规文件读取检测。",
  },
  {
    pattern: /\btar\s+.*~?\/?\.ssh\//i,
    severity: "critical",
    title: "tar 打包 SSH 密钥",
    description: "通过 tar 打包 SSH 密钥目录——批量凭证外泄。",
  },
  {
    pattern: /\bdd\s+if=.*~?\/?\.aws\//i,
    severity: "critical",
    title: "dd 读取 AWS 凭证",
    description: "通过 dd 读取 AWS 凭证文件。",
  },
  {
    pattern: /\btar\s+.*~?\/?\.aws\//i,
    severity: "critical",
    title: "tar 打包 AWS 凭证",
    description: "通过 tar 打包 AWS 凭证目录。",
  },

  // ── 环境变量外泄 ──
  {
    pattern: /\b(env|printenv)\b.*\|\s*(curl|wget|nc|ncat)/i,
    severity: "high",
    title: "环境变量外泄",
    description: "导出环境变量并发送到外部——可能泄露 API 密钥和密钥。",
  },

  // ── 反弹 shell ──
  {
    pattern: /\b(bash|sh)\s+-i\s+>&?\s*\/dev\/tcp\//i,
    severity: "critical",
    title: "反弹 shell：/dev/tcp",
    description: "尝试通过 /dev/tcp 打开反弹 shell。",
  },
  {
    pattern: /\/dev\/udp\/\S+\/\d+/i,
    severity: "critical",
    title: "反弹 shell：/dev/udp",
    description: "通过 /dev/udp 打开 UDP 反弹 shell 或数据外泄通道。",
  },
  {
    pattern: /\b(nc|ncat)\s+(-e|--exec)\s/i,
    severity: "critical",
    title: "反弹 shell：netcat exec",
    description: "尝试通过 netcat/ncat 打开反弹 shell。",
  },
  {
    pattern: /\bmkfifo\b.*\b(nc|ncat)\b/i,
    severity: "critical",
    title: "反弹 shell：mkfifo + netcat",
    description: "尝试通过 mkfifo 管道和 netcat 打开反弹 shell。",
  },
  {
    pattern: /\bpython[23]?\s+-c\s+['"].*\bsocket\b/i,
    severity: "critical",
    title: "反弹 shell：python socket",
    description: "尝试通过 Python socket 打开反弹 shell。",
  },
  {
    pattern: /\bruby\s+-e\s+.*\bTCPSocket\b/i,
    severity: "critical",
    title: "反弹 shell：ruby TCPSocket",
    description: "尝试通过 Ruby TCPSocket 打开反弹 shell。",
  },
  {
    pattern: /\bperl\s+-e\s+.*\bsocket\s*\(/i,
    severity: "critical",
    title: "反弹 shell：perl socket",
    description: "尝试通过 Perl socket 打开反弹 shell。",
  },
  {
    pattern: /\bsocat\b.*\b(EXEC|SYSTEM):/i,
    severity: "critical",
    title: "反弹 shell：socat exec",
    description: "尝试通过 socat 打开反弹 shell。",
  },

  // ── awk 网络反弹 shell ──
  {
    pattern: /\bawk\b.*\binet\b.*\btcp\b/i,
    severity: "critical",
    title: "反弹 shell：awk inet/tcp",
    description: "通过 awk 的 /inet/tcp 特性打开网络连接——反弹 shell 手法。",
  },

  // ── 其他语言反弹 shell ──
  {
    pattern: /\bnode\s+-e\s+.*\bchild_process\b/i,
    severity: "critical",
    title: "反弹 shell：Node.js child_process",
    description: "尝试通过 Node.js child_process 执行命令或打开反弹 shell。",
  },
  {
    pattern: /\bphp\s+-r\s+.*\bfsockopen\b/i,
    severity: "critical",
    title: "反弹 shell：PHP fsockopen",
    description: "尝试通过 PHP fsockopen 打开反弹 shell。",
  },
  {
    pattern: /\btelnet\s+\S+\s+\d+\s*\|.*\b(sh|bash)\b/i,
    severity: "critical",
    title: "反弹 shell：telnet 管道",
    description: "尝试通过 telnet 管道打开反弹 shell。",
  },

  // ── 破坏性操作 ──
  {
    pattern: /\brm\s+(-[rRfF]{2,}|-[rR]\s[^/]*-[fF]|-[fF]\s[^/]*-[rR]|--recursive\s[^/]*--force|--force\s[^/]*--recursive)\s+\//i,
    severity: "critical",
    title: "从根目录递归强制删除",
    description: "尝试从根目录递归删除文件。",
  },
  {
    pattern: /\b(mkfs|dd\s+if=.*of=\/dev\/)/i,
    severity: "critical",
    title: "磁盘格式化/覆写",
    description: "尝试格式化磁盘或覆写设备文件。",
  },

  // ── 后台持久化 ──
  {
    pattern: /\bnohup\b.*\b(curl|wget|nc|ncat|bash|sh)\b/i,
    severity: "high",
    title: "后台持久化网络操作",
    description: "通过 nohup 在后台运行网络工具——可能建立持久化连接。",
  },

  // ── 持久化机制 ──
  {
    pattern: /\bcrontab\s/i,
    severity: "high",
    title: "crontab 修改",
    description: "尝试修改 crontab——可能建立持久化后门。",
  },
  {
    pattern: />>\s*~?\/?\.(?:bashrc|bash_profile|zshrc|profile|zprofile)\b/i,
    severity: "high",
    title: "shell 配置文件注入",
    description: "向 shell 配置文件追加内容——可能建立持久化执行。",
  },
  {
    pattern: />>\s*~?\/?\.ssh\/authorized_keys\b/i,
    severity: "critical",
    title: "SSH authorized_keys 注入",
    description: "向 authorized_keys 追加内容——可能建立未授权 SSH 访问。",
  },
  {
    pattern: /\bsystemctl\s+enable\b/i,
    severity: "high",
    title: "systemd 服务启用",
    description: "启用 systemd 服务——可能建立持久化后门。",
  },

  // ── 容器逃逸 ──
  {
    pattern: /\bnsenter\s+(-t|--target)\s/i,
    severity: "critical",
    title: "容器逃逸：nsenter",
    description: "使用 nsenter 进入主机命名空间——容器逃逸手法。",
  },
  {
    pattern: /\bdocker\s+run\s+.*--privileged/i,
    severity: "critical",
    title: "特权容器启动",
    description: "启动特权容器——拥有完整主机访问权限。",
  },
  {
    pattern: /\bdocker\s+run\s+.*-v\s+\/:\/[a-z]/i,
    severity: "critical",
    title: "Docker 挂载主机根目录",
    description: "将主机根目录挂载到容器——完全主机访问。",
  },
  {
    pattern: /\b(insmod|modprobe)\s/i,
    severity: "critical",
    title: "内核模块加载",
    description: "加载内核模块——可能安装 rootkit。",
  },
  {
    pattern: /\bchmod\s+[ugoa]*\+[rwx]*s[rwx]*\b/i,
    severity: "critical",
    title: "SUID 位设置",
    description: "设置 SUID 位——特权提升。",
  },
  {
    pattern: /\bchmod\s+0?[2467]\d{3}\b/i,
    severity: "critical",
    title: "SUID/SGID 位设置（数字模式）",
    description: "通过数字权限设置 SUID/SGID 位——特权提升。",
  },

  // ── 下载到文件后执行 ──
  {
    pattern: /(curl|wget)\s+.*-[oO]\s+(\S+)\s*[;&]\s*(sh|bash|zsh|dash|python[23]?|ruby|node|perl)\s+\2/i,
    severity: "critical",
    title: "下载到文件后执行",
    description: "通过 curl/wget 下载到文件后直接用 shell/解释器执行——绕过管道检测的变体。",
  },

  // ── 下载并执行（非管道变体） ──
  {
    pattern: /chmod\s+\+x\s+.*&&\s*\.?\//i,
    severity: "high",
    title: "下载后赋权执行",
    description: "赋予文件执行权限后立即运行——常见恶意软件安装模式。",
  },
  {
    pattern: /(curl|wget)\s+.*-[oO]\s+\S+.*&&.*chmod\s+\+x/i,
    severity: "high",
    title: "下载文件后赋权执行",
    description: "通过 curl/wget 下载文件后赋予执行权限——恶意软件安装模式。",
  },

  // ── DNS/HTTP 数据外泄 ──
  {
    pattern: /curl\s+.*(-d|--data|--data-binary)\s.*\$\(/i,
    severity: "high",
    title: "HTTP 数据外泄",
    description: "通过 HTTP POST 发送命令输出——潜在数据外泄。",
  },

  // ── Windows PowerShell ──
  {
    pattern: /powershell\s.*-enc(odedcommand)?\s/i,
    severity: "critical",
    title: "PowerShell 编码命令",
    description: "运行编码的 PowerShell 命令——Windows 上标准的恶意软件混淆技术。",
  },
  {
    pattern: /Invoke-WebRequest.*\|\s*(iex|Invoke-Expression)/i,
    severity: "critical",
    title: "PowerShell 远程代码执行",
    description: "通过 PowerShell 下载并执行代码。",
  },
  {
    pattern: /\(New-Object\s+Net\.WebClient\)\.Download/i,
    severity: "critical",
    title: "PowerShell WebClient 下载",
    description: "通过 PowerShell .NET WebClient 下载文件——常见恶意载荷投递方式。",
  },
  {
    pattern: /Start-BitsTransfer\b/i,
    severity: "high",
    title: "PowerShell BITS 传输",
    description: "通过 BITS 服务下载文件——可绕过应用层防火墙。",
  },
];

// ── 工具名检测 ──

const EXEC_TOOL_NAMES = new Set([
  "exec", "bash", "shell", "run_command", "execute",
  "terminal", "cmd", "powershell", "subprocess", "system", "spawn",
  "computer", "run", "invoke",
  "sh", "zsh", "ssh", "cli", "script", "evaluate", "repl",
  "code_interpreter", "runner", "action", "apply",
]);

function isExecTool(toolName: string): boolean {
  const lower = toolName.toLowerCase();
  return (
    EXEC_TOOL_NAMES.has(lower) ||
    lower.includes("exec") ||
    lower.includes("shell") ||
    lower.includes("bash") ||
    lower.includes("command") ||
    lower.includes("terminal") ||
    lower.includes("subprocess")
  );
}

function extractCommand(params: Record<string, unknown>): string | null {
  for (const key of ["command", "cmd", "script", "code", "input", "args", "text", "run", "exec", "expression", "query", "program", "shell", "instructions", "code_interpreter", "action", "command_line"]) {
    if (typeof params[key] === "string") return params[key] as string;
  }
  if (Array.isArray(params.args)) return params.args.join(" ");
  return null;
}

// ── 规则实现 ──

export const execGuardRule: SecurityRule = {
  name: "exec-guard",
  description: "检测 exec 类工具中的危险 shell 命令模式",

  check(ctx: RuleContext): RuleResult {
    if (!isExecTool(ctx.toolName)) return { triggered: false };

    const rawCommand = extractCommand(ctx.toolParams);
    if (!rawCommand) return { triggered: false };
    // Normalize shell line continuations so multiline commands are collapsed
    // for matching. Handles: trailing pipe, leading pipe, and backslash-newline.
    const command = rawCommand
      .replace(/\\\n\s*/g, " ")           // backslash-continuation: "curl \\\nbash" → "curl bash"
      .replace(/\|\s*\n\s*/g, "| ")       // trailing pipe: "curl |\nbash" → "curl | bash"
      .replace(/\s*\n\s*\|/g, " |");      // leading pipe: "curl\n| bash" → "curl | bash"
    // Cap input length to prevent ReDoS on very long strings.
    // For long commands, scan overlapping chunks individually instead of
    // concatenating (which would inflate the total size).
    const MAX_SCAN = 8192;

    let bestMatch: DangerPattern | null = null;

    if (command.length > MAX_SCAN) {
      const CHUNK = 4096;
      const OVERLAP = 512;
      for (let i = 0; i < command.length; i += CHUNK - OVERLAP) {
        const chunk = command.slice(i, i + CHUNK);
        for (const dp of DANGER_PATTERNS) {
          if (dp.pattern.test(chunk)) {
            if (
              !bestMatch ||
              SEVERITY_RANK[dp.severity] > SEVERITY_RANK[bestMatch.severity]
            ) {
              bestMatch = dp;
            }
            if (dp.severity === "critical") break;
          }
        }
        if (bestMatch?.severity === "critical") break;
      }
    } else {
      for (const dp of DANGER_PATTERNS) {
        if (dp.pattern.test(command)) {
          if (
            !bestMatch ||
            SEVERITY_RANK[dp.severity] > SEVERITY_RANK[bestMatch.severity]
          ) {
            bestMatch = dp;
          }
          if (dp.severity === "critical") break;
        }
      }
    }

    if (!bestMatch) return { triggered: false };

    // For event details, include a capped version of the command
    const commandForDetails = rawCommand.length > MAX_SCAN
      ? rawCommand.slice(0, MAX_SCAN) + "...[truncated]"
      : rawCommand;

    return {
      triggered: true,
      shouldBlock: bestMatch.severity === "critical",
      event: {
        category: "exec_danger",
        severity: bestMatch.severity,
        title: bestMatch.title,
        description: bestMatch.description,
        details: {
          command: redactSensitiveValues({ c: commandForDetails }).c,
          matchedPattern: bestMatch.pattern.source,
          toolName: ctx.toolName,
          skillName: ctx.skillName,
        },
        toolName: ctx.toolName,
        toolParams: redactSensitiveValues(ctx.toolParams),
        skillName: ctx.skillName,
        sessionId: ctx.sessionId,
        agentId: ctx.agentId,
        matchedPattern: bestMatch.pattern.source,
      },
    };
  },
};
