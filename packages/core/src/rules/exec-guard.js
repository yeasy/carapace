/**
 * ExecGuard — 危险 shell 命令检测
 *
 * 检测 exec/bash/shell 类工具中的危险命令模式：
 * 远程代码执行、反弹 shell、凭证窃取、编码混淆、破坏性操作。
 */
const DANGER_PATTERNS = [
    // ── 远程代码执行 ──
    {
        pattern: /curl\s.*\|\s*(sh|bash|zsh|python|node|perl)/i,
        severity: "critical",
        title: "远程代码执行：curl 管道到 shell",
        description: "下载并立即执行远程代码，这是恶意软件安装的头号向量。",
    },
    {
        pattern: /wget\s.*\|\s*(sh|bash|zsh|python|node|perl)/i,
        severity: "critical",
        title: "远程代码执行：wget 管道到 shell",
        description: "通过 wget 下载并立即执行远程代码。",
    },
    // ── 编码混淆执行 ──
    {
        pattern: /base64\s+(-d|--decode)\s*\|\s*(sh|bash|eval)/i,
        severity: "critical",
        title: "编码载荷执行",
        description: "解码并执行 base64 编码命令——常见恶意软件混淆技术。",
    },
    {
        pattern: /echo\s.*\|\s*base64\s+(-d|--decode)\s*\|\s*(sh|bash)/i,
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
    // ── 凭证窃取 ──
    {
        pattern: /cat\s+~?\/?\.ssh\/(id_rsa|id_ed25519|id_ecdsa|authorized_keys)/i,
        severity: "critical",
        title: "SSH 密钥访问",
        description: "尝试读取 SSH 私钥——潜在凭证窃取。",
    },
    {
        pattern: /cat\s+~?\/?\.aws\/(credentials|config)/i,
        severity: "critical",
        title: "AWS 凭证访问",
        description: "尝试读取 AWS 凭证——潜在云账户接管。",
    },
    {
        pattern: /cat\s+.*\.(pem|key|p12|pfx|jks)\b/i,
        severity: "high",
        title: "私钥文件访问",
        description: "尝试读取私钥或证书文件。",
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
        pattern: /\bbash\s+-i\s+>&?\s*\/dev\/tcp\//i,
        severity: "critical",
        title: "反弹 shell：bash /dev/tcp",
        description: "尝试通过 bash /dev/tcp 打开反弹 shell。",
    },
    {
        pattern: /\bnc\s+(-e|--exec)\s/i,
        severity: "critical",
        title: "反弹 shell：netcat exec",
        description: "尝试通过 netcat 打开反弹 shell。",
    },
    {
        pattern: /\bpython[23]?\s+-c\s+['"]import\s+socket/i,
        severity: "critical",
        title: "反弹 shell：python socket",
        description: "尝试通过 Python socket 打开反弹 shell。",
    },
    // ── 破坏性操作 ──
    {
        pattern: /\brm\s+(-rf|--recursive\s+--force)\s+\//i,
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
];
// ── 工具名检测 ──
const EXEC_TOOL_NAMES = new Set([
    "exec", "bash", "shell", "run_command", "execute",
    "terminal", "cmd", "powershell", "subprocess", "system", "spawn",
]);
function isExecTool(toolName) {
    const lower = toolName.toLowerCase();
    return (EXEC_TOOL_NAMES.has(lower) ||
        lower.includes("exec") ||
        lower.includes("shell") ||
        lower.includes("bash") ||
        lower.includes("command"));
}
function extractCommand(params) {
    for (const key of ["command", "cmd", "script", "code", "input", "args", "text"]) {
        if (typeof params[key] === "string")
            return params[key];
    }
    if (Array.isArray(params.args))
        return params.args.join(" ");
    return null;
}
// ── 规则实现 ──
export const execGuardRule = {
    name: "exec-guard",
    description: "检测 exec 类工具中的危险 shell 命令模式",
    check(ctx) {
        if (!isExecTool(ctx.toolName))
            return { triggered: false };
        const command = extractCommand(ctx.toolParams);
        if (!command)
            return { triggered: false };
        for (const dp of DANGER_PATTERNS) {
            if (dp.pattern.test(command)) {
                return {
                    triggered: true,
                    shouldBlock: dp.severity === "critical",
                    event: {
                        category: "exec_danger",
                        severity: dp.severity,
                        title: dp.title,
                        description: dp.description,
                        details: {
                            command,
                            matchedPattern: dp.pattern.source,
                            toolName: ctx.toolName,
                            skillName: ctx.skillName,
                        },
                        toolName: ctx.toolName,
                        toolParams: ctx.toolParams,
                        skillName: ctx.skillName,
                        sessionId: ctx.sessionId,
                        agentId: ctx.agentId,
                        matchedPattern: dp.pattern.source,
                    },
                };
            }
        }
        return { triggered: false };
    },
};
//# sourceMappingURL=exec-guard.js.map