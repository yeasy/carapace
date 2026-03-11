# Changelog

All notable changes to this project will be documented in this file.

## [0.5.0] - 2026-03-11

### Added
- **Dashboard Web UI** (`@carapace/dashboard`): Real-time security monitoring dashboard with embedded dark-theme HTML interface, SSE live event push, and comprehensive REST API (`/api/events`, `/api/stats`, `/api/timeseries`, `/api/policies`, `/api/health`).
- **EventStore**: In-memory event database with query filters (category, severity, rule, session, time range), pagination, statistics aggregation, and time series bucketing. Configurable max capacity with automatic eviction.
- **SIEM connectors**: 4 enterprise connectors — Splunk HEC (`SplunkSink`), Elasticsearch bulk API (`ElasticSink`), Datadog Logs API (`DatadogSink`), and Syslog RFC 5424 (`SyslogSink`) with UDP/TCP support.
- **Team policy management** (`PolicyManager`): Multi-policy CRUD with inheritance chains, circular dependency detection, override merging (forceBlock, disabledRules, additionalTrustedSkills), JSON import/export, and 3 preset templates (permissive, standard, strict).
- New test suite: 28 dashboard tests (257 total across all packages).

### Changed
- Monorepo expanded to 5 packages: core + 3 adapters + dashboard.
- All package versions bumped to 0.5.0.
- Root build/test scripts updated for dashboard package.

## [0.4.0] - 2026-03-11

### Added
- **YAML custom rules**: Define security rules via YAML files without writing TypeScript. Supports tool name matching, parameter pattern matching, and any-parameter scanning. Multi-document YAML supported.
- **MCP proxy adapter** (`@carapace/adapter-mcp`): Transparent stdio proxy for MCP (Model Context Protocol) servers. Intercepts `tools/call` requests, applies all security rules, and returns JSON-RPC errors for blocked calls. Includes response data-exfil scanning.
- **LangChain/CrewAI Python bridge** (`@carapace/adapter-langchain`): HTTP bridge server for Python agent frameworks. Exposes `/check`, `/check/batch`, `/status`, and `/health` endpoints. Includes Python client library example.
- New test suites: 12 YAML rule tests, 12 MCP proxy tests, 12 bridge tests (229 total).

### Changed
- Monorepo expanded: 4 packages (core + 3 adapters).
- Root build/test scripts updated for all packages.
- Both adapters support YAML custom rule loading via `yamlRules` config option.

## [0.3.0] - 2026-03-11

### Added
- **PromptInjection rule**: 19 patterns detecting prompt injection attempts in tool parameters — role overrides, system prompt leaks, jailbreak attempts (DAN, developer mode), encoding bypasses, fake system tags, and indirect injection markers.
- **DataExfil rule**: 14+ patterns detecting data exfiltration — credential leaks (AWS keys, GitHub tokens, OpenAI/Stripe keys, private keys), file uploads via curl, environment variable leaks, pipe exfil patterns. 12 known exfil destination services (transfer.sh, file.io, ngrok, webhook.site, etc.).
- **BaselineDrift rule**: Per-skill behavior baseline modeling with configurable learning threshold (default 20 calls). Detects novel tool usage after learning phase completes.
- **Session statistics**: Per-session counters tracking tool calls, blocked calls, and alerts fired, with summary logged on session end.
- **Response data-exfil scanning**: `after_tool_call` hook now scans tool results for credential leak patterns.

### Changed
- Adapter now registers 5 always-on rules (ExecGuard, PathGuard, NetworkGuard, PromptInjection, DataExfil) plus optional RateLimiter and BaselineDrift.
- Adapter version string updated to v0.3.0.
- Configuration expanded: `enableBaseline` (boolean), `maxToolCallsPerMinute` (number).
- Test suite expanded from 161 to 195 tests.

## [0.2.0] - 2026-03-11

### Added
- **RateLimiter rule**: Sliding-window rate limiting per session, configurable via `maxToolCallsPerMinute`. Triggers medium/high/critical alerts based on how far the rate exceeds the threshold (1x/1.5x/2x).
- **ESLint configuration**: Flat config with `@typescript-eslint` rules for code quality enforcement.
- **GitHub Actions CI**: Automated lint, build, and test on push/PR for Node 20 and 22.
- **CHANGELOG.md**: This file.

### Changed
- User-provided regex patterns in `sensitivePathPatterns` and `blockedDomains` are now validated with try-catch — invalid patterns are silently skipped instead of crashing the runtime.
- `WebhookSink` and `LogFileSink` now log errors to stderr on failure instead of silently swallowing exceptions.
- TypeScript badge updated to `5.4+` to reflect minimum requirement.
- PNG assets optimized (logo 1.7 MB → 163 KB, icon 351 KB → 56 KB).

### Removed
- Unused `licenseKey` field from `CarapaceConfig`.
- Extraneous `@carapace/pro` reference in `package-lock.json`.

## [0.1.0] - 2026-03-09

### Added
- Core rule engine with trusted-skill bypass.
- **ExecGuard**: 18 patterns detecting dangerous shell commands (rm -rf /, curl | sh, etc.).
- **PathGuard**: 20+ patterns detecting access to SSH keys, cloud credentials, browser data, crypto wallets, system auth files.
- **NetworkGuard**: 6 categories detecting suspicious network activity (ngrok, pastebin, crypto mining, C2 domains, etc.).
- Alert routing with `ConsoleSink`, `WebhookSink`, `LogFileSink` and 5-minute deduplication.
- OpenClaw adapter with `before_tool_call` blocking and `after_tool_call` observability hooks.
- Comprehensive test suite (161 tests).
- Bilingual documentation (Chinese + English): README, design docs.
