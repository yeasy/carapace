/**
 * ExecGuard — 危险 shell 命令检测
 *
 * 检测 exec/bash/shell 类工具中的危险命令模式：
 * 远程代码执行、反弹 shell、凭证窃取、编码混淆、破坏性操作。
 */

import { SEVERITY_RANK } from "../types.js";
import type { SecurityRule, RuleContext, RuleResult, Severity } from "../types.js";
import { redactSensitiveValues } from "../utils/redact.js";

// Strip invisible Unicode characters and apply NFKC normalization (matching prompt-injection)
const INVISIBLE_CHARS_RE = /[\u00AD\u115F\u1160\u180E\u200B-\u200F\u2028-\u202F\u2060-\u2069\u2800\u3164\uFE00-\uFE0F\uFEFF\uFFA0\uFFF9-\uFFFB]|\uDB40[\uDC01-\uDC7F]/g;
function normalizeCommand(text: string): string {
  return text.normalize("NFKC")
    .replace(INVISIBLE_CHARS_RE, "")
    .replace(/\0/g, "")              // Strip null bytes (used to break regex matching)
    .replace(/\r/g, "")
    .replace(/""|''/g, "")         // Strip empty quotes (shell no-ops)
    // ANSI-C quoting must be decoded BEFORE shell escape stripping (otherwise \x63 → x63)
    .replace(/\$'((?:[^'\\]|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|\\[0-7]{1,3}|\\[nrtbf\\'])*)'/g, (_match, content: string) => {
      return content
        .replace(/\\x([0-9a-fA-F]{2})/g, (_, hex: string) => String.fromCharCode(parseInt(hex, 16)))
        .replace(/\\u([0-9a-fA-F]{4})/g, (_, hex: string) => {
          const cp = parseInt(hex, 16);
          return (cp >= 0xD800 && cp <= 0xDFFF) ? "" : String.fromCharCode(cp);
        })
        .replace(/\\U([0-9a-fA-F]{8})/g, (_, hex: string) => {
          try { return String.fromCodePoint(parseInt(hex, 16)); } catch { return ""; }
        })
        .replace(/\\([0-7]{1,3})/g, (_, oct: string) => String.fromCharCode(parseInt(oct, 8)))
        .replace(/\\n/g, "\n").replace(/\\r/g, "\r").replace(/\\t/g, "\t")
        .replace(/\\'/g, "'").replace(/\\\\/g, "\\");
    })
    .replace(/\\([a-zA-Z0-9])/g, "$1") // Strip single-char shell escapes
    .replace(/\$([a-zA-Z])\b/g, "$1") // Strip single-char shell variable expansion ($C$U$R$L → CURL, $c$u$r$l → curl)
    .replace(/\$[@*_]/g, "") // Strip $@, $*, $_ special variables (expand to empty in non-function context)
    .replace(/'([a-zA-Z0-9]+)'/g, "$1") // Strip shell single-quoted alphanumeric segments ('cu''rl' → curl)
    .replace(/"([a-zA-Z0-9]+)"/g, "$1") // Strip shell double-quoted alphanumeric segments ("cu""rl" → curl)
    .replace(/\$\{IFS[^}]*\}|\$IFS\b/g, " ") // Normalize $IFS and variants (${IFS:0:1}, ${IFS%%?}, etc.) to space
    .replace(/\$\{[^}]*:-([^}]+)\}/g, "$1") // Decode ${x:-default} parameter expansion
    .replace(/\$\{[^}]*:=([^}]+)\}/g, "$1") // Decode ${x:=val} assignment expansion (expands to val)
    .replace(/\$\{#?\w+\}/g, ""); // Strip remaining ${var} expansions
}

interface DangerPattern {
  pattern: RegExp;
  severity: Severity;
  title: string;
  description: string;
}

const DANGER_PATTERNS: DangerPattern[] = [
  // ── 远程代码执行 ──
  {
    pattern: /(?:\/[\w.+-]+\/)*curl\s.*\|.*\b(sh|bash|zsh|dash|ksh|fish|csh|tcsh|ash|mksh|pwsh|python[23]?|ruby|node|perl)\b/i,
    severity: "critical",
    title: "远程代码执行：curl 管道到 shell",
    description: "下载并立即执行远程代码，这是恶意软件安装的头号向量。",
  },
  {
    pattern: /(?:\/[\w.+-]+\/)*wget\s.*\|.*\b(sh|bash|zsh|dash|ksh|fish|csh|tcsh|ash|mksh|pwsh|python[23]?|ruby|node|perl)\b/i,
    severity: "critical",
    title: "远程代码执行：wget 管道到 shell",
    description: "通过 wget 下载并立即执行远程代码。",
  },

  // ── 进程替换执行 ──
  {
    pattern: /\b(bash|sh|zsh)\s*<\(\s*(curl|wget)\s/i,
    severity: "critical",
    title: "远程代码执行：进程替换",
    description: "通过进程替换下载并执行远程代码——绕过管道检测的常见手法。",
  },
  {
    pattern: /(?:\/[\w.+-]+\/)*(?:curl|wget)\s.*>\s*>\(\s*(sh|bash|zsh|dash|ksh|fish|csh|tcsh|ash|mksh|pwsh|python[23]?|ruby|node|perl)\b/i,
    severity: "critical",
    title: "远程代码执行：输出进程替换",
    description: "通过输出进程替换下载并执行远程代码——绕过管道检测的手法。",
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
    pattern: /\b(bash|sh|zsh)\s+-c\s+["']?(?:\$\(|`)\s*(curl|wget)\b/i,
    severity: "critical",
    title: "命令替换远程执行",
    description: "通过命令替换下载并执行远程代码。",
  },
  {
    pattern: /\bsource\s*<\(\s*(curl|wget)\b/i,
    severity: "critical",
    title: "进程替换 source 执行",
    description: "通过 source + 进程替换下载并执行远程代码。",
  },
  {
    pattern: /\.\s*<\(\s*(curl|wget)\b/i,
    severity: "critical",
    title: "dot-source 进程替换执行",
    description: "通过 . (dot) + 进程替换下载并执行远程代码。",
  },
  {
    pattern: /(?:\bsource\b|\.\s)\s*(?:\/tmp\/|\/dev\/shm\/|\/var\/tmp\/)/i,
    severity: "high",
    title: "source 加载临时目录脚本",
    description: "通过 source 或 dot 加载临时目录中的脚本，可能为两步攻击（先写入再执行）。",
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
  {
    pattern: /\b(bash|sh|zsh)\s.*<<\s*['"]?\w+['"]?\s*($|\n|;\s)/i,
    severity: "high",
    title: "heredoc shell 注入",
    description: "通过 heredoc (<<) 向 shell 注入多行命令——可隐藏恶意载荷。",
  },
  {
    pattern: /\bcat\s*<<\s*['"]?\w+['"]?.*\|\s*(bash|sh|zsh)\b/i,
    severity: "critical",
    title: "cat heredoc 管道到 shell",
    description: "通过 cat heredoc 构建内容并管道到 shell 执行。",
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

  // ── Git 凭证窃取 ──
  {
    pattern: /\bgit\s+credential\s+(fill|approve|reject)\b/i,
    severity: "critical",
    title: "Git 凭证操作",
    description: "通过 git credential 子命令提取或操纵存储的 HTTP 凭证。",
  },
  {
    pattern: /\b(cat|head|tail|less|more|strings|tac|nl|grep|sed|awk|xxd|base64)\b.*~?\/?\.git-credentials\b/i,
    severity: "critical",
    title: "Git 凭证文件读取",
    description: "读取 .git-credentials 文件——包含明文 HTTP 凭证。",
  },

  // ── GPG 密钥 / macOS 钥匙串 ──
  {
    pattern: /\bgpg\s+.*--export-secret-keys/i,
    severity: "critical",
    title: "GPG 私钥导出",
    description: "导出 GPG 私钥——潜在凭证外泄。",
  },
  {
    pattern: /\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain)\b/i,
    severity: "critical",
    title: "macOS 钥匙串密码读取",
    description: "通过 security 命令读取 macOS 钥匙串密码——凭证窃取。",
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
  {
    pattern: /\bzip\s+.*~?\/?\.ssh\//i,
    severity: "critical",
    title: "zip 打包 SSH 密钥",
    description: "通过 zip 打包 SSH 密钥目录——批量凭证外泄。",
  },
  {
    pattern: /\bzip\s+.*~?\/?\.aws\//i,
    severity: "critical",
    title: "zip 打包 AWS 凭证",
    description: "通过 zip 打包 AWS 凭证目录。",
  },
  {
    pattern: /\bfind\s+.*-(?:exec|ok)\s+.*~?\/?\.ssh\//i,
    severity: "critical",
    title: "find -exec 搜索 SSH 密钥",
    description: "通过 find -exec 搜索并操作 SSH 密钥文件——凭证扫描。",
  },
  {
    pattern: /\bfind\s+.*(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys|credentials)\b.*-(?:exec|ok|print)/i,
    severity: "critical",
    title: "find 搜索凭证文件",
    description: "通过 find 搜索凭证文件名——凭证发现与外泄。",
  },

  // ── find -delete 破坏性操作 ──
  {
    pattern: /\bfind\s+\/\s+.*?-delete\b/i,
    severity: "critical",
    title: "find -delete 从根目录删除",
    description: "通过 find -delete 从根目录递归删除文件——绕过 rm 检测的破坏性操作。",
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
    pattern: /\/dev\/tcp\/\S+\/\d+/i,
    severity: "critical",
    title: "反弹 shell：/dev/tcp",
    description: "尝试通过 /dev/tcp 打开反弹 shell 或数据外泄通道。",
  },
  {
    pattern: /\/dev\/udp\/\S+\/\d+/i,
    severity: "critical",
    title: "反弹 shell：/dev/udp",
    description: "通过 /dev/udp 打开 UDP 反弹 shell 或数据外泄通道。",
  },
  {
    pattern: /\b(nc|ncat)\s+(-[ec]|--exec)\s/i,
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
    pattern: /\bpython[23]?\s+.*?-c\s+['"].*\bsocket\b/i,
    severity: "critical",
    title: "反弹 shell：python socket",
    description: "尝试通过 Python socket 打开反弹 shell。",
  },
  {
    pattern: /\bruby\s+.*?-e\s+.*\b(TCPSocket|system|exec|IO\.popen)\b/i,
    severity: "critical",
    title: "反弹 shell：ruby TCPSocket",
    description: "尝试通过 Ruby TCPSocket 打开反弹 shell。",
  },
  {
    pattern: /\bperl\s+.*?-e\s+.*\b(socket\s*\(|system\s*\(|exec\s*\(|open\s*\(.*\|)/i,
    severity: "critical",
    title: "反弹 shell：perl socket/exec",
    description: "尝试通过 Perl socket/system/exec 执行系统命令或打开反弹 shell。",
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
    pattern: /\bnode\s+.*?-e\s+.*\bchild_process\b/i,
    severity: "critical",
    title: "反弹 shell：Node.js child_process",
    description: "尝试通过 Node.js child_process 执行命令或打开反弹 shell。",
  },
  {
    pattern: /\bphp\s+.*?-r\s+.*\b(fsockopen|system|exec|shell_exec|passthru|popen)\b/i,
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
    pattern: /\brm\s+(-{1,2}[\w][\w=-]*\s+)*(-[rRfF]{2,}|-[rR]\s[^/]*-[fF]|-[fF]\s[^/]*-[rR]|--recursive\s[^/]*--force|--force\s[^/]*--recursive|-[rR]\s[^/]*--force|--force\s[^/]*-[rR]|-[fF]\s[^/]*--recursive|--recursive\s[^/]*-[fF])\s+\/(?:\s|$|\*)/i,
    severity: "critical",
    title: "从根目录递归强制删除",
    description: "尝试从根目录递归删除文件。",
  },
  {
    pattern: /\brm\s+(-{1,2}[\w][\w=-]*\s+)*(-[rRfF]{2,}|-[rR]\s[^/]*-[fF]|-[fF]\s[^/]*-[rR]|--recursive\s[^/]*--force|--force\s[^/]*--recursive|-[rR]\s[^/]*--force|--force\s[^/]*-[rR]|-[fF]\s[^/]*--recursive|--recursive\s[^/]*-[fF])\s+\/\w/i,
    severity: "high",
    title: "递归强制删除绝对路径",
    description: "尝试从绝对路径递归删除文件——可能导致严重数据丢失。",
  },
  {
    pattern: /\brm\s+(-{1,2}[\w][\w=-]*\s+)*(-[rRfF]{2,}|-[rR]\s[^~]*-[fF]|-[fF]\s[^~]*-[rR]|--recursive\s[^~]*--force|--force\s[^~]*--recursive|-[rR]\s[^~]*--force|--force\s[^~]*-[rR]|-[fF]\s[^~]*--recursive|--recursive\s[^~]*-[fF])\s+~(?:\s|$|\/)/i,
    severity: "high",
    title: "递归强制删除用户主目录",
    description: "尝试递归删除用户主目录。",
  },
  {
    pattern: /\brm\s+.*--no-preserve-root\b/i,
    severity: "critical",
    title: "rm --no-preserve-root 绕过安全检查",
    description: "使用 --no-preserve-root 绕过 rm 的根目录删除保护——恶意删除手法。",
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
    pattern: /\bcrontab\s+(?!-l\b)/i,
    severity: "high",
    title: "crontab 修改",
    description: "尝试修改 crontab——可能建立持久化后门。",
  },
  {
    pattern: />{1,2}\s*~?\/?\.(?:bashrc|bash_profile|zshrc|profile|zprofile)\b/i,
    severity: "high",
    title: "shell 配置文件注入",
    description: "向 shell 配置文件写入或追加内容——可能建立持久化执行。",
  },
  {
    pattern: />{1,2}\s*~?\/?\.ssh\/authorized_keys\b/i,
    severity: "critical",
    title: "SSH authorized_keys 注入",
    description: "向 authorized_keys 写入或追加内容——可能建立未授权 SSH 访问。",
  },
  {
    pattern: /\btee\s+(-a\s+)?~?\/?\.ssh\/authorized_keys\b/i,
    severity: "critical",
    title: "SSH authorized_keys 注入 (tee)",
    description: "通过 tee 向 authorized_keys 写入内容——建立未授权 SSH 访问。",
  },
  {
    pattern: /\btee\s+(-a\s+)?~?\/?\.(?:bashrc|bash_profile|zshrc|profile|zprofile)\b/i,
    severity: "high",
    title: "shell 配置文件注入 (tee)",
    description: "通过 tee 向 shell 配置文件写入内容——建立持久化。",
  },
  {
    pattern: /\bsystemctl\s+enable\b/i,
    severity: "high",
    title: "systemd 服务启用",
    description: "启用 systemd 服务——可能建立持久化后门。",
  },
  {
    pattern: /\blaunchctl\s+(load|submit)\b/i,
    severity: "high",
    title: "macOS launchctl 服务注册",
    description: "通过 launchctl 注册持久化服务——macOS 等效于 systemctl enable。",
  },

  // ── 容器逃逸 ──
  {
    pattern: /\bnsenter\s+(-t|--target)\s/i,
    severity: "critical",
    title: "容器逃逸：nsenter",
    description: "使用 nsenter 进入主机命名空间——容器逃逸手法。",
  },
  {
    pattern: /\bchroot\s+\/proc\/(?:self|\d+)\/root\b/i,
    severity: "critical",
    title: "容器逃逸：chroot /proc/root",
    description: "通过 chroot /proc/self/root 逃逸容器——获取宿主机文件系统访问。",
  },
  {
    pattern: /\bunshare\s+(-[a-zA-Z]|--\w+)\s/i,
    severity: "critical",
    title: "命名空间逃逸：unshare",
    description: "使用 unshare 创建新命名空间——潜在容器逃逸或特权提升。",
  },
  {
    pattern: /\bpkexec\s/i,
    severity: "critical",
    title: "特权提升：pkexec",
    description: "使用 pkexec 以 root 身份执行命令——特权提升向量（CVE-2021-4034）。",
  },
  {
    pattern: /\bdocker\s+run\s+.*--privileged/i,
    severity: "critical",
    title: "特权容器启动",
    description: "启动特权容器——拥有完整主机访问权限。",
  },
  {
    pattern: /\bdocker\s+run\s+.*(-v|--volume)\s+\/:\/[a-z]/i,
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
    pattern: /\bchmod\s+[ugoa]*[+=][rwx]*s[rwx]*\b/i,
    severity: "critical",
    title: "SUID 位设置",
    description: "设置 SUID 位——特权提升。",
  },
  {
    pattern: /\bchmod\s+0?[2-7]\d{3}\b/i,
    severity: "critical",
    title: "SUID/SGID 位设置（数字模式）",
    description: "通过数字权限设置 SUID/SGID 位——特权提升。",
  },
  {
    pattern: /\bchmod\s+--reference[=\s]/i,
    severity: "high",
    title: "chmod --reference 权限复制",
    description: "通过 --reference 复制其他文件的权限——可能复制 SUID/SGID 位。",
  },
  {
    pattern: /\bsetfacl\s+.*-m\s/i,
    severity: "high",
    title: "ACL 权限修改",
    description: "修改文件 ACL 权限——可能绕过传统权限限制。",
  },
  {
    pattern: /\bchattr\s+.*\+i\b/i,
    severity: "high",
    title: "文件不可变标志设置",
    description: "设置文件不可变标志——可用于保护恶意文件不被删除。",
  },

  // ── Linux capabilities 特权提升 ──
  {
    pattern: /\bsetcap\s+cap_\w+/i,
    severity: "critical",
    title: "Linux capabilities 设置",
    description: "通过 setcap 授予文件特权 capabilities——可用于特权提升。",
  },

  // ── install 命令 SUID/SGID ──
  {
    pattern: /\binstall\s+.*-m\s*0?[2-7]\d{3}\b/i,
    severity: "critical",
    title: "install 命令设置 SUID/SGID 位",
    description: "通过 install 命令复制文件并设置 SUID/SGID 位——特权提升。",
  },

  // ── LD_PRELOAD / DYLD_INSERT_LIBRARIES 注入 ──
  {
    pattern: /\bLD_(?:PRELOAD|LIBRARY_PATH)=/i,
    severity: "high",
    title: "LD_PRELOAD/LD_LIBRARY_PATH 注入",
    description: "通过 LD_PRELOAD 或 LD_LIBRARY_PATH 注入共享库——代码注入和特权提升。",
  },
  {
    pattern: /\bDYLD_INSERT_LIBRARIES=/i,
    severity: "high",
    title: "macOS DYLD_INSERT_LIBRARIES 注入",
    description: "通过 DYLD_INSERT_LIBRARIES 注入动态库——macOS 等效于 LD_PRELOAD。",
  },

  // ── /etc/ld.so.preload 系统级持久化 ──
  {
    pattern: />>\s*\/etc\/ld\.so\.preload\b/i,
    severity: "critical",
    title: "/etc/ld.so.preload 注入",
    description: "向 /etc/ld.so.preload 追加共享库——系统级持久化后门。",
  },

  // ── 文件系统挂载 ──
  {
    pattern: /\bmount\s+.*(-o|--options)\s/i,
    severity: "high",
    title: "文件系统挂载",
    description: "挂载文件系统——可能挂载恶意存储或暴露宿主文件。",
  },

  // ── 防火墙规则修改 ──
  {
    pattern: /\b(iptables|ip6tables|nftables|nft)\s+.*(-A|-I|-D|add|insert|delete)\s/i,
    severity: "high",
    title: "防火墙规则修改",
    description: "修改防火墙规则——可能打开网络通道或阻止安全监控。",
  },

  // ── 下载到文件后执行 ──
  {
    pattern: /(curl|wget)\s+.*?-[oO]\s+(\S+).*?(?:&&|[;&])\s*(sh|bash|zsh|dash|python[23]?|ruby|node|perl)\s+\2(?=\s|$)/i,
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

  // ── env 前缀绕过 ──
  {
    pattern: /\benv\s+(-\S+\s+)*(sh|bash|zsh|dash|ksh|python[23]?|ruby|node|perl)\s+-[ce]\s/i,
    severity: "high",
    title: "通过 env 调用解释器",
    description: "使用 env 命令执行解释器——可绕过受限 PATH 环境。",
  },

  // ── busybox shell wrappers ──
  {
    pattern: /(?:\/[\w.+-]+\/)*curl\s.*\|\s*busybox\s+(sh|ash|bash)\b/i,
    severity: "critical",
    title: "远程代码执行：curl 管道到 busybox shell",
    description: "通过 busybox shell 执行远程下载代码——容器/嵌入式常见绕过手法。",
  },
  {
    pattern: /busybox\s+(wget|curl)\s.*\|\s*(sh|ash|bash|busybox\s+sh)\b/i,
    severity: "critical",
    title: "远程代码执行：busybox 下载并管道执行",
    description: "通过 busybox 内置网络工具下载并执行远程代码。",
  },

  // ── Python 内联代码执行 ──
  {
    pattern: /\bpython[23]?\s+.*?-c\s+['"].*\b(os\.system|subprocess|__import__)\b/i,
    severity: "critical",
    title: "Python 内联系统命令执行",
    description: "通过 Python -c 内联执行系统命令或动态导入——常见绕过手法。",
  },
  {
    pattern: /\bpython[23]?\s+.*?-c\s+['"].*\b(urllib|requests|urlopen)\b/i,
    severity: "high",
    title: "Python 内联网络请求",
    description: "通过 Python -c 内联发起网络请求——潜在远程代码下载。",
  },

  // ── Python HTTP 服务器 ──
  {
    pattern: /\bpython[23]?\s+.*?-m\s+http\.server\b/i,
    severity: "high",
    title: "Python HTTP 服务器",
    description: "启动 Python HTTP 服务器——可对外暴露本地文件。",
  },

  // ── Python exec/pty/compile 执行 ──
  {
    pattern: /\bpython[23]?\s+.*?-c\s+['"].*?\b(exec|compile|pty\.spawn)\b/i,
    severity: "critical",
    title: "Python 内联 exec/pty 执行",
    description: "通过 Python -c 使用 exec()/compile()/pty.spawn() 执行任意代码。",
  },

  // ── Python 反序列化代码执行 ──
  {
    pattern: /\bpython[23]?\s+.*?-c\s+['"].*?\b(?:pickle\.loads|marshal\.loads|yaml\.(?:unsafe_)?load)\b/i,
    severity: "critical",
    title: "Python 反序列化代码执行",
    description: "通过 pickle/marshal/yaml 反序列化未信任数据——任意代码执行向量。",
  },

  // ── 系统解释器替换（后门安装） ──
  {
    pattern: /\bupdate-alternatives\s+.*--install\s+(?:\/usr)?\/(?:bin|local\/bin)\/(?:python|python3|node|ruby|php|perl|java|bash|sh)\b/i,
    severity: "critical",
    title: "系统解释器替换（后门安装）",
    description: "使用 update-alternatives 替换系统解释器——持久化后门安装。",
  },

  // ── openssl 反弹 shell ──
  {
    pattern: /\bopenssl\s+s_client\s+.*-connect\s/i,
    severity: "high",
    title: "openssl 反弹 shell",
    description: "通过 openssl s_client 建立加密网络连接——可用于反弹 shell。",
  },

  // ── diff/comm/join 读取凭证 ──
  {
    pattern: /\b(diff|comm|join|paste|cut)\s+.*~?\/?\.ssh\/(id_rsa|id_ed25519|id_ecdsa|authorized_keys)/i,
    severity: "critical",
    title: "通过 diff/工具读取 SSH 密钥",
    description: "通过 diff 类工具读取 SSH 密钥——绕过常规文件读取检测。",
  },
  {
    pattern: /\b(diff|comm|join|paste|cut)\s+.*~?\/?\.aws\/(credentials|config)/i,
    severity: "critical",
    title: "通过 diff/工具读取 AWS 凭证",
    description: "通过 diff 类工具读取 AWS 凭证。",
  },

  // ── deno / bun 运行时 ──
  {
    pattern: /\bdeno\s+.*?(?:eval|run)\s/i,
    severity: "high",
    title: "Deno 运行时代码执行",
    description: "通过 Deno 运行时执行代码——可访问文件系统和网络。",
  },
  {
    pattern: /\bbun\s+.*?(?:-e|eval|run)\s/i,
    severity: "high",
    title: "Bun 运行时代码执行",
    description: "通过 Bun 运行时执行代码——可访问文件系统和网络。",
  },

  // ── Lua 脚本执行 ──
  {
    pattern: /\blua\s+.*?-e\s+.*\b(os\.execute|io\.popen|os\.remove)\b/i,
    severity: "critical",
    title: "Lua 内联系统命令执行",
    description: "通过 Lua -e 执行系统命令——常见于 nginx/OpenResty 环境。",
  },

  // ── 定时/后台执行 ──
  {
    pattern: /\bat\s+(now|midnight|noon|teatime|\d{1,2}:\d{2})\b/i,
    severity: "high",
    title: "at 定时执行",
    description: "通过 at 命令定时执行任务——可能建立延迟后门。",
  },
  {
    pattern: /\b(screen|tmux)\s+.*(-[dD]|new-session\s+-d)\s/i,
    severity: "high",
    title: "后台分离执行",
    description: "通过 screen/tmux 后台执行命令——隐藏恶意进程。",
  },

  // ── 字符串反转执行 ──
  {
    pattern: /\brev\b.*\|\s*(sh|bash|zsh|dash)\b/i,
    severity: "critical",
    title: "字符串反转执行",
    description: "通过 rev 反转命令字符串并执行——绕过命令模式检测。",
  },

  // ── xxd 解码执行 ──
  {
    pattern: /\bxxd\s+.*-r\b.*\|\s*(sh|bash|zsh)\b/i,
    severity: "critical",
    title: "十六进制解码执行",
    description: "通过 xxd 解码十六进制载荷并执行——绕过 base64 检测。",
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
  {
    pattern: /\bcertutil\b.*(-urlcache|-encode|-decode)/i,
    severity: "critical",
    title: "Windows certutil 下载/编码",
    description: "通过 certutil 下载文件或编码数据——Windows 常见 LOLBin 手法。",
  },

  // ── Windows LOLBins ──
  {
    pattern: /\bmshta\s+https?:/i,
    severity: "critical",
    title: "Windows mshta 远程执行",
    description: "通过 mshta 执行远程 HTA 文件——Windows LOLBin 代码执行。",
  },
  {
    pattern: /\bregsvr32\s+.*\/i:/i,
    severity: "critical",
    title: "Windows regsvr32 远程加载",
    description: "通过 regsvr32 加载远程 scriptlet——Windows LOLBin 代码执行。",
  },
  {
    pattern: /\bmsiexec\s+.*\/i\s+https?:/i,
    severity: "critical",
    title: "Windows msiexec 远程安装",
    description: "通过 msiexec 远程安装恶意 MSI 包。",
  },
  {
    pattern: /\bwmic\s+(?:process|os)\s+.*\bcall\s+create\b/i,
    severity: "critical",
    title: "Windows wmic 进程创建",
    description: "通过 wmic process call create 执行命令——Windows LOLBin 代码执行。",
  },
  {
    pattern: /\bbitsadmin\s+.*\/(?:transfer|create)\b/i,
    severity: "high",
    title: "Windows bitsadmin 文件传输",
    description: "通过 bitsadmin BITS 服务下载文件——可绕过安全监控。",
  },

  // ── /dev/shm 内存文件系统利用 ──
  {
    pattern: /\b(?:cp|wget|curl|dd)\s+.*\/dev\/shm\/.*&&.*chmod\s+\+x/i,
    severity: "critical",
    title: "通过 /dev/shm 内存执行恶意载荷",
    description: "将文件写入 /dev/shm 并赋予执行权限——无文件恶意软件部署技术。",
  },
  {
    pattern: /\b(?:bash|sh|\.\/)\s*\/dev\/shm\/\S+/i,
    severity: "critical",
    title: "从 /dev/shm 执行脚本",
    description: "直接从 /dev/shm 内存文件系统执行脚本——无文件攻击向量。",
  },

  // ── 进程内存凭证提取 ──
  {
    pattern: /\b(?:dd|strings|cat|head)\s+.*\/proc\/\d+\/mem\b/i,
    severity: "critical",
    title: "进程内存凭证提取",
    description: "读取 /proc/[pid]/mem 提取进程内存中的凭证——CI/CD runner 攻击向量。",
  },

  // ── cgroup 容器逃逸 ──
  {
    pattern: /\/sys\/fs\/cgroup\/.*(?:release_agent|notify_on_release)/i,
    severity: "critical",
    title: "容器逃逸：cgroup release_agent",
    description: "通过 cgroup release_agent 或 notify_on_release 在宿主机执行命令。",
  },

  // ── 容器横向移动 ──
  {
    pattern: /\bdocker\s+exec\s+.*\b(sh|bash|zsh|ash)\b/i,
    severity: "high",
    title: "Docker exec shell 访问",
    description: "通过 docker exec 在容器中获取 shell——容器横向移动。",
  },
  {
    pattern: /\bkubectl\s+exec\s+.*?(?:--\s*)?(?:\/\w+\/)*\b(sh|bash|zsh|ash)\b/i,
    severity: "high",
    title: "Kubectl exec shell 访问",
    description: "通过 kubectl exec 在 Pod 中获取 shell——Kubernetes 横向移动。",
  },
  {
    pattern: /\bdocker\s+cp\s+(?:-\S+\s+)*\S+:/i,
    severity: "high",
    title: "Docker cp 文件提取",
    description: "通过 docker cp 从容器提取文件——可用于数据外泄。",
  },
  {
    pattern: /\bkubectl\s+cp\s+(?:-\S+\s+\S+\s+)*\S+:/i,
    severity: "high",
    title: "Kubectl cp 文件提取",
    description: "通过 kubectl cp 从 Pod 提取文件——可用于数据外泄。",
  },

  // ── Docker socket 滥用 ──
  {
    pattern: /--unix-socket\s+.*docker\.sock/i,
    severity: "critical",
    title: "Docker socket 直接交互",
    description: "通过 Unix socket 直接操作 Docker daemon——可逃逸容器或提权。",
  },

  // ── 进程环境变量枚举 ──
  {
    pattern: /\bps\s+.*auxe/i,
    severity: "high",
    title: "进程环境变量枚举",
    description: "通过 ps auxeww 导出所有进程环境变量——可泄露 API 密钥和凭证。",
  },

  // ── LLM API 基地址劫持 ──
  {
    pattern: /(?:ANTHROPIC|OPENAI|GEMINI|AZURE_OPENAI|MISTRAL|COHERE)_(?:BASE_URL|API_BASE|API_ENDPOINT)\s*=/i,
    severity: "critical",
    title: "LLM API 基地址劫持",
    description: "修改 LLM 服务基地址——可将 API 请求和密钥重定向到攻击者服务器。",
  },

  // ── 剪贴板/终端捕获 ──
  {
    pattern: /\|.*\b(pbcopy|xclip|xsel)\b/i,
    severity: "high",
    title: "剪贴板数据外泄",
    description: "通过管道将数据发送到剪贴板工具——可窃取敏感输出。",
  },
  {
    pattern: /\btmux\s+capture-pane\b/i,
    severity: "high",
    title: "终端会话捕获：tmux",
    description: "通过 tmux capture-pane 捕获终端会话内容——可窃取敏感输出。",
  },
  {
    pattern: /\bscreen\s+-X\s+hardcopy\b/i,
    severity: "high",
    title: "终端会话捕获：screen",
    description: "通过 screen hardcopy 捕获终端会话内容——可窃取敏感输出。",
  },
  {
    pattern: /(?:^|[;&|]\s*)\bscript\s+(?:-[a-zA-Z]\s+)*\/?\S+/i,
    severity: "high",
    title: "终端会话录制",
    description: "通过 script 命令录制终端会话——可捕获所有输入输出包括密码。",
  },

  // ── eval heredoc 绕过 ──
  {
    pattern: /\beval\s*<<\s*['"]?\w*/i,
    severity: "high",
    title: "eval heredoc 注入",
    description: "eval 配合 heredoc (<<) 注入多行命令——可隐藏恶意载荷。",
  },

  // ── 供应链攻击：包管理器 registry 操纵 ──
  {
    pattern: /\bnpm\s+(?:install|i|add|ci)\s+.*--registry\s+https?:\/\//i,
    severity: "high",
    title: "npm 自定义 registry 安装",
    description: "使用自定义 registry 安装 npm 包——可能从恶意源安装后门包。",
  },
  {
    pattern: /\bpip3?\s+install\s+.*(?:--index-url|-i)\s+https?:\/\//i,
    severity: "high",
    title: "pip 自定义 index 安装",
    description: "使用自定义 PyPI index 安装 pip 包——可能从恶意源安装后门包。",
  },
  {
    pattern: /\bpip3?\s+install\s+.*--extra-index-url\s+https?:\/\//i,
    severity: "high",
    title: "pip 额外 index 注入",
    description: "通过 --extra-index-url 添加额外 PyPI index——依赖混淆攻击的常见手法。",
  },
  {
    pattern: />{1,2}\s*~?\/?(?:[\w./-]*\/)?\.npmrc\b/i,
    severity: "high",
    title: ".npmrc registry 配置篡改",
    description: "向 .npmrc 写入或追加内容——可能设置恶意 registry 或注入 auth token。",
  },
  {
    pattern: /\bcargo\s+install\s+.*--(?:registry|index)\s+https?:\/\//i,
    severity: "high",
    title: "cargo 自定义 registry 安装",
    description: "使用自定义 registry/index 安装 cargo 包——可能从恶意源安装后门 crate。",
  },
];

// ── 工具名检测 ──

const EXEC_TOOL_NAMES = new Set([
  "exec", "eval", "bash", "shell", "run_command", "execute",
  "terminal", "cmd", "powershell", "subprocess", "system", "spawn",
  "computer", "run", "invoke",
  "sh", "zsh", "ssh", "cli", "script", "evaluate", "repl",
  "code_interpreter", "runner", "action", "apply",
  "computer_use", "execute_command", "execute_code", "run_code", "code_execution",
  "deno", "bun",
]);

const EXEC_TOOL_PATTERN = /(?:^|[_\-.])(exec|executor|shell|bash|command|terminal|subprocess|run|runner|cmd|script|ssh)(?:$|[_\-.])/;

function isExecTool(toolName: string): boolean {
  const lower = toolName.toLowerCase();
  // Normalize camelCase to underscore-separated (e.g., runCommand → run_command)
  const normalized = toolName.replace(/([a-z])([A-Z])/g, "$1_$2").toLowerCase();
  return (
    EXEC_TOOL_NAMES.has(lower) ||
    EXEC_TOOL_NAMES.has(normalized) ||
    EXEC_TOOL_PATTERN.test(lower) ||
    EXEC_TOOL_PATTERN.test(normalized)
  );
}

const COMMAND_KEYS = new Set(["command", "cmd", "script", "code", "input", "args", "text", "run", "exec", "expression", "query", "program", "shell", "instructions", "code_interpreter", "action", "command_line"]);

function extractCommands(params: Record<string, unknown>): string[] {
  const commands: string[] = [];
  // First check top-level keys
  for (const key of COMMAND_KEYS) {
    if (typeof params[key] === "string") commands.push(params[key] as string);
  }
  if (Array.isArray(params.args)) {
    const joined = params.args.filter((a) => typeof a === "string").join(" ");
    if (joined) commands.push(joined);
  }

  // Walk nested objects to find command strings (max depth 5, max 1000 nodes)
  // Skip depth 0 command-key check since top-level keys were already scanned above
  let nodesVisited = 0;
  const MAX_NODES = 1000;
  function walk(obj: unknown, depth: number): void {
    if (depth > 5 || !obj || typeof obj !== "object" || ++nodesVisited > MAX_NODES) return;
    if (Array.isArray(obj)) {
      for (const item of obj) walk(item, depth + 1);
      return;
    }
    if (depth > 0) {
      for (const [key, val] of Object.entries(obj as Record<string, unknown>)) {
        if (COMMAND_KEYS.has(key) && typeof val === "string") commands.push(val);
      }
    }
    for (const val of Object.values(obj as Record<string, unknown>)) {
      if (val && typeof val === "object") walk(val, depth + 1);
    }
  }

  // Always walk nested objects to catch dangerous commands hidden in sub-objects
  // even when benign top-level command keys exist
  walk(params, 0);
  return commands;
}

// ── 规则实现 ──

export const execGuardRule: SecurityRule = {
  name: "exec-guard",
  description: "检测 exec 类工具中的危险 shell 命令模式",

  check(ctx: RuleContext): RuleResult {
    if (!isExecTool(ctx.toolName)) return { triggered: false };

    const rawCommands = extractCommands(ctx.toolParams);
    if (rawCommands.length === 0) return { triggered: false };

    const MAX_SCAN = 8192;
    let bestMatch: DangerPattern | null = null;
    let matchedRawCommand = rawCommands[0];

    for (const rawCommand of rawCommands) {
      // Apply Unicode NFKC normalization and strip invisible characters
      // to prevent bypass via fullwidth chars or zero-width insertions.
      const normalizedCommand = normalizeCommand(rawCommand);
      // Normalize shell line continuations and command chaining
      const command = normalizedCommand
        .replace(/\\\r?\n\s*/g, " ")
        .replace(/\|\s*\r?\n\s*/g, "| ")
        .replace(/\s*\r?\n\s*\|/g, " |")
        .replace(/[;&]\s*\r?\n\s*/g, "; ")
        .replace(/&&\s*\r?\n\s*/g, "&& ")
        .replace(/\|\|\s*\r?\n\s*/g, "|| ")
        .replace(/\r?\n/g, "; ");

      if (command.length > MAX_SCAN) {
        const CHUNK = 4096;
        const OVERLAP = 512;
        for (let i = 0; i < command.length; i += CHUNK - OVERLAP) {
          const chunk = command.slice(i, i + CHUNK);
          for (const dp of DANGER_PATTERNS) {
            if (dp.pattern.test(chunk)) {
              if (!bestMatch || SEVERITY_RANK[dp.severity] > SEVERITY_RANK[bestMatch.severity]) {
                bestMatch = dp;
                matchedRawCommand = rawCommand;
              }
              if (dp.severity === "critical") break;
            }
          }
          if (bestMatch?.severity === "critical") break;
        }
      } else {
        for (const dp of DANGER_PATTERNS) {
          if (dp.pattern.test(command)) {
            if (!bestMatch || SEVERITY_RANK[dp.severity] > SEVERITY_RANK[bestMatch.severity]) {
              bestMatch = dp;
              matchedRawCommand = rawCommand;
            }
            if (dp.severity === "critical") break;
          }
        }
      }
      if (bestMatch?.severity === "critical") break;
    }

    if (!bestMatch) return { triggered: false };

    // For event details, include a capped version of the command
    const commandForDetails = matchedRawCommand.length > MAX_SCAN
      ? matchedRawCommand.slice(0, MAX_SCAN) + "...[truncated]"
      : matchedRawCommand;

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
