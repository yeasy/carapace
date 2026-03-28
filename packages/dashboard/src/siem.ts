/**
 * SIEM 连接器 — 将 Carapace 事件转发到外部 SIEM 平台
 *
 * 支持:
 * - Splunk HEC (HTTP Event Collector)
 * - Elastic/ELK (Elasticsearch bulk API)
 * - Datadog (Logs API)
 * - 通用 Syslog (RFC 5424 over TCP/UDP)
 * - 自定义 HTTP 端点
 */

import type { SecurityEvent, AlertSink, AlertPayload } from "@carapace/core";

// ── Splunk HEC ──

export interface SplunkConfig {
  /** Splunk HEC endpoint URL (e.g. https://splunk.example.com:8088/services/collector/event) */
  endpoint: string;
  /** HEC token */
  token: string;
  /** Splunk index (optional) */
  index?: string;
  /** Source type (default: carapace) */
  sourceType?: string;
}

export class SplunkSink implements AlertSink {
  readonly name = "splunk";
  private config: SplunkConfig;

  constructor(config: SplunkConfig) {
    // Validate URL to prevent SSRF — only allow http/https
    try {
      const parsed = new URL(config.endpoint);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        throw new Error(`SplunkSink only supports http/https URLs, got: ${parsed.protocol}`);
      }
    } catch (err) {
      if (err instanceof TypeError) {
        throw new Error(`SplunkSink: invalid URL "${config.endpoint}"`);
      }
      throw err;
    }
    this.config = config;
  }

  async send(payload: AlertPayload): Promise<void> {
    const body = JSON.stringify({
      event: this.formatEvent(payload.event),
      sourcetype: this.config.sourceType ?? "carapace",
      ...(this.config.index ? { index: this.config.index } : {}),
    });

    try {
      const response = await fetch(this.config.endpoint, {
        method: "POST",
        headers: {
          Authorization: `Splunk ${this.config.token}`,
          "Content-Type": "application/json",
        },
        body,
      });
      if (!response.ok) {
        process.stderr.write(
          `[carapace-splunk] HTTP ${response.status}: ${await response.text()}\n`
        );
      }
    } catch (err) {
      process.stderr.write(`[carapace-splunk] Error: ${err}\n`);
    }
  }

  private formatEvent(event: SecurityEvent): Record<string, unknown> {
    return {
      timestamp: new Date(event.timestamp).toISOString(),
      severity: event.severity,
      category: event.category,
      title: event.title,
      description: event.description,
      rule: event.ruleName,
      tool: event.toolName,
      skill: event.skillName,
      session: event.sessionId,
      agent: event.agentId,
      action: event.action,
      matched_pattern: event.matchedPattern,
      details: event.details,
    };
  }
}

// ── Elasticsearch / ELK ──

export interface ElasticConfig {
  /** Elasticsearch URL (e.g. https://elastic.example.com:9200) */
  endpoint: string;
  /** Index name (default: carapace-events) */
  index?: string;
  /** API key for authentication (optional) */
  apiKey?: string;
  /** Username for basic auth (optional) */
  username?: string;
  /** Password for basic auth (optional) */
  password?: string;
}

export class ElasticSink implements AlertSink {
  readonly name = "elastic";
  private config: ElasticConfig;

  constructor(config: ElasticConfig) {
    // Validate URL to prevent SSRF — only allow http/https
    try {
      const parsed = new URL(config.endpoint);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        throw new Error(`ElasticSink only supports http/https URLs, got: ${parsed.protocol}`);
      }
    } catch (err) {
      if (err instanceof TypeError) {
        throw new Error(`ElasticSink: invalid URL "${config.endpoint}"`);
      }
      throw err;
    }
    this.config = config;
  }

  async send(payload: AlertPayload): Promise<void> {
    const index = this.config.index ?? "carapace-events";
    const base = new URL(this.config.endpoint);
    base.pathname = base.pathname.replace(/\/$/, "") + `/${index}/_doc`;
    const url = base.toString();

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.config.apiKey) {
      headers["Authorization"] = `ApiKey ${this.config.apiKey}`;
    } else if (this.config.username && this.config.password) {
      headers["Authorization"] =
        "Basic " +
        Buffer.from(`${this.config.username}:${this.config.password}`).toString(
          "base64"
        );
    }

    const body = JSON.stringify({
      "@timestamp": new Date(payload.event.timestamp).toISOString(),
      severity: payload.event.severity,
      category: payload.event.category,
      title: payload.event.title,
      description: payload.event.description,
      rule_name: payload.event.ruleName,
      tool_name: payload.event.toolName,
      skill_name: payload.event.skillName,
      session_id: payload.event.sessionId,
      agent_id: payload.event.agentId,
      action: payload.event.action,
      matched_pattern: payload.event.matchedPattern,
      details: payload.event.details,
    });

    try {
      const response = await fetch(url, { method: "POST", headers, body });
      if (!response.ok) {
        process.stderr.write(
          `[carapace-elastic] HTTP ${response.status}: ${await response.text()}\n`
        );
      }
    } catch (err) {
      process.stderr.write(`[carapace-elastic] Error: ${err}\n`);
    }
  }
}

// ── Datadog Logs ──

export interface DatadogConfig {
  /** Datadog API key */
  apiKey: string;
  /** Datadog site (default: datadoghq.com) */
  site?: string;
  /** Service name (default: carapace) */
  service?: string;
  /** Tags (e.g. ["env:production", "team:security"]) */
  tags?: string[];
}

export class DatadogSink implements AlertSink {
  readonly name = "datadog";
  private config: DatadogConfig;

  private static readonly VALID_SITES = new Set([
    "datadoghq.com",
    "datadoghq.eu",
    "ddog-gov.com",
    "ap1.datadoghq.com",
    "us3.datadoghq.com",
    "us5.datadoghq.com",
  ]);

  constructor(config: DatadogConfig) {
    const site = config.site ?? "datadoghq.com";
    if (!DatadogSink.VALID_SITES.has(site)) {
      throw new Error(`DatadogSink: unknown site "${site}". Valid sites: ${[...DatadogSink.VALID_SITES].join(", ")}`);
    }
    this.config = config;
  }

  async send(payload: AlertPayload): Promise<void> {
    const site = this.config.site ?? "datadoghq.com";
    const url = `https://http-intake.logs.${site}/api/v2/logs`;

    const body = JSON.stringify([
      {
        ddsource: "carapace",
        ddtags: (this.config.tags ?? []).join(","),
        hostname: "carapace-agent",
        service: this.config.service ?? "carapace",
        status: this.severityToDatadog(payload.event.severity),
        message: payload.summary,
        timestamp: payload.event.timestamp,
        attributes: {
          severity: payload.event.severity,
          category: payload.event.category,
          title: payload.event.title,
          rule: payload.event.ruleName,
          tool: payload.event.toolName,
          skill: payload.event.skillName,
          session: payload.event.sessionId,
          action: payload.event.action,
        },
      },
    ]);

    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "DD-API-KEY": this.config.apiKey,
          "Content-Type": "application/json",
        },
        body,
      });
      if (!response.ok) {
        process.stderr.write(
          `[carapace-datadog] HTTP ${response.status}: ${await response.text()}\n`
        );
      }
    } catch (err) {
      process.stderr.write(`[carapace-datadog] Error: ${err}\n`);
    }
  }

  private severityToDatadog(severity: string): string {
    switch (severity) {
      case "critical":
        return "critical";
      case "high":
        return "error";
      case "medium":
        return "warn";
      case "low":
        return "info";
      default:
        return "info";
    }
  }
}

// ── Syslog (RFC 5424 格式) ──

export interface SyslogConfig {
  /** Syslog server host */
  host: string;
  /** Syslog server port (default: 514) */
  port?: number;
  /** Protocol (default: udp) */
  protocol?: "udp" | "tcp";
  /** Facility (default: 1 = user) */
  facility?: number;
  /** App name (default: carapace) */
  appName?: string;
}

export class SyslogSink implements AlertSink {
  readonly name = "syslog";
  private config: SyslogConfig;

  constructor(config: SyslogConfig) {
    // Validate host to prevent injection
    if (/[\/\?#@:]/.test(config.host)) {
      throw new Error(`SyslogSink: invalid host "${config.host}"`);
    }
    this.config = config;
  }

  async send(payload: AlertPayload): Promise<void> {
    const facility = this.config.facility ?? 1;
    const severity = this.syslogSeverity(payload.event.severity);
    const priority = facility * 8 + severity;
    const appName = this.config.appName ?? "carapace";
    const timestamp = new Date(payload.event.timestamp).toISOString();

    const message =
      `<${priority}>1 ${timestamp} carapace-agent ${appName} - - - ` +
      `[${payload.event.category}] ${payload.event.action.toUpperCase()}: ${payload.event.title}` +
      ` | rule=${payload.event.ruleName} tool=${payload.event.toolName} severity=${payload.event.severity}`;

    const protocol = this.config.protocol ?? "udp";
    const port = this.config.port ?? 514;

    try {
      if (protocol === "udp") {
        const { createSocket } = await import("node:dgram");
        const client = createSocket("udp4");
        const buf = Buffer.from(message);
        await new Promise<void>((resolve) => {
          client.on("error", (err) => {
            process.stderr.write(`[carapace-syslog] UDP error: ${err}\n`);
            try { client.close(); } catch { /* ignore */ }
            resolve();
          });
          client.send(buf, 0, buf.length, port, this.config.host, (err) => {
            if (err) process.stderr.write(`[carapace-syslog] UDP send error: ${err}\n`);
            try { client.close(); } catch { /* ignore */ }
            resolve();
          });
        });
      } else {
        const { createConnection } = await import("node:net");
        const client = createConnection(port, this.config.host, () => {
          client.write(message + "\n");
          client.end();
        });
        client.on("error", (err) => {
          process.stderr.write(`[carapace-syslog] TCP error: ${err}\n`);
        });
      }
    } catch (err) {
      process.stderr.write(`[carapace-syslog] Error: ${err}\n`);
    }
  }

  private syslogSeverity(severity: string): number {
    switch (severity) {
      case "critical":
        return 2; // Critical
      case "high":
        return 3; // Error
      case "medium":
        return 4; // Warning
      case "low":
        return 5; // Notice
      default:
        return 6; // Informational
    }
  }
}
