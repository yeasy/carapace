# Changelog

All notable changes to this project will be documented in this file.

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
