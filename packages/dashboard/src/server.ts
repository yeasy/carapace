/**
 * Dashboard HTTP 服务器
 *
 * 提供:
 * - REST API: 事件查询、统计、策略管理
 * - 内嵌 Web Dashboard UI (单 HTML 页面)
 * - SSE (Server-Sent Events) 实时事件推送
 */

import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import type { SecurityEvent, AlertSink, AlertPayload } from "@carapace/core";
import { EventStore, type EventQuery } from "./event-store.js";
import { PolicyManager, type PolicyDefinition } from "./policy.js";

export interface DashboardConfig {
  /** HTTP 端口 (default: 9877) */
  port?: number;
  /** 绑定地址 (default: 127.0.0.1) */
  host?: string;
  /** CORS 来源 (default: *) */
  corsOrigin?: string;
  /** 最大存储事件数 (default: 10000) */
  maxEvents?: number;
}

export class DashboardServer {
  private store: EventStore;
  private policyManager: PolicyManager;
  private config: DashboardConfig;
  private server: ReturnType<typeof createServer> | null = null;
  private sseClients: Set<ServerResponse> = new Set();

  constructor(config: DashboardConfig = {}) {
    this.config = config;
    this.store = new EventStore(config.maxEvents ?? 10000);
    this.policyManager = new PolicyManager();
  }

  /**
   * 获取 EventStore 实例（供外部 sink 使用）
   */
  getStore(): EventStore {
    return this.store;
  }

  /**
   * 获取 PolicyManager 实例
   */
  getPolicyManager(): PolicyManager {
    return this.policyManager;
  }

  /**
   * 创建 AlertSink，将事件写入 dashboard 存储
   */
  createSink(): AlertSink {
    return {
      name: "dashboard",
      send: async (payload: AlertPayload) => {
        this.store.add(payload.event);
        this.broadcastSSE(payload.event);
      },
    };
  }

  /**
   * 推送 SSE 事件
   */
  private broadcastSSE(event: SecurityEvent): void {
    const data = JSON.stringify({
      id: event.id,
      timestamp: event.timestamp,
      severity: event.severity,
      category: event.category,
      title: event.title,
      action: event.action,
      ruleName: event.ruleName,
      toolName: event.toolName,
    });
    for (const client of this.sseClients) {
      try {
        client.write(`data: ${data}\n\n`);
      } catch {
        this.sseClients.delete(client);
      }
    }
  }

  /**
   * 启动 HTTP 服务
   */
  async start(): Promise<void> {
    const port = this.config.port ?? 9877;
    const host = this.config.host ?? "127.0.0.1";
    const cors = this.config.corsOrigin ?? "*";

    this.server = createServer(
      (req: IncomingMessage, res: ServerResponse) => {
        res.setHeader("Access-Control-Allow-Origin", cors);
        res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", "Content-Type");

        if (req.method === "OPTIONS") {
          res.writeHead(204);
          res.end();
          return;
        }

        const url = req.url ?? "/";
        this.route(req, res, url);
      }
    );

    return new Promise((resolve) => {
      this.server!.listen(port, host, () => {
        resolve();
      });
    });
  }

  /**
   * 停止 HTTP 服务
   */
  async stop(): Promise<void> {
    for (const client of this.sseClients) {
      try { client.end(); } catch { /* ignore */ }
    }
    this.sseClients.clear();

    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  private route(req: IncomingMessage, res: ServerResponse, url: string): void {
    // ── Dashboard UI ──
    if (req.method === "GET" && (url === "/" || url === "/dashboard")) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(DASHBOARD_HTML);
      return;
    }

    // ── SSE endpoint ──
    if (req.method === "GET" && url === "/api/events/stream") {
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      });
      this.sseClients.add(res);
      req.on("close", () => this.sseClients.delete(res));
      req.on("error", () => this.sseClients.delete(res));
      // 定期发送心跳，帮助检测死连接
      const heartbeat = setInterval(() => {
        try {
          if (res.destroyed) {
            this.sseClients.delete(res);
            clearInterval(heartbeat);
            return;
          }
          res.write(":heartbeat\n\n");
        } catch {
          this.sseClients.delete(res);
          clearInterval(heartbeat);
        }
      }, 30_000);
      req.on("close", () => clearInterval(heartbeat));
      return;
    }

    // ── API Routes ──
    if (req.method === "GET" && url === "/api/health") {
      this.json(res, { status: "ok" });
      return;
    }

    if (req.method === "GET" && url.startsWith("/api/events")) {
      const params = new URL(url, "http://localhost").searchParams;
      const query: EventQuery = {};
      if (params.get("category")) query.category = params.get("category") as any;
      if (params.get("severity")) query.severity = params.get("severity") as any;
      if (params.get("ruleName")) query.ruleName = params.get("ruleName")!;
      if (params.get("since")) query.since = parseInt(params.get("since")!);
      if (params.get("limit")) query.limit = parseInt(params.get("limit")!);
      if (params.get("offset")) query.offset = parseInt(params.get("offset")!);

      const events = this.store.query(query);
      this.json(res, events);
      return;
    }

    if (req.method === "GET" && url.startsWith("/api/stats")) {
      const params = new URL(url, "http://localhost").searchParams;
      const since = params.get("since")
        ? parseInt(params.get("since")!)
        : undefined;
      const stats = this.store.getStats(since);
      this.json(res, stats);
      return;
    }

    if (req.method === "GET" && url.startsWith("/api/timeseries")) {
      const params = new URL(url, "http://localhost").searchParams;
      const bucketMs = parseInt(params.get("bucket") ?? "60000");
      const since = params.get("since")
        ? parseInt(params.get("since")!)
        : undefined;
      const ts = this.store.timeSeries(bucketMs, since);
      this.json(res, ts);
      return;
    }

    // ── Policy API ──
    if (req.method === "GET" && url === "/api/policies") {
      this.json(res, this.policyManager.listPolicies());
      return;
    }

    if (req.method === "GET" && url === "/api/policies/active") {
      const active = this.policyManager.resolveActivePolicy();
      this.json(res, active ?? { name: null });
      return;
    }

    if (req.method === "POST" && url === "/api/policies") {
      this.readBody(req, (body) => {
        try {
          const policy = JSON.parse(body) as PolicyDefinition;
          policy.createdAt = policy.createdAt ?? Date.now();
          policy.updatedAt = Date.now();
          this.policyManager.addPolicy(policy);
          this.json(res, { ok: true, name: policy.name }, 201);
        } catch {
          this.json(res, { error: "Invalid policy JSON" }, 400);
        }
      });
      return;
    }

    if (req.method === "PUT" && url.startsWith("/api/policies/active/")) {
      const name = url.split("/").pop()!;
      try {
        this.policyManager.setActivePolicy(name);
        this.json(res, { ok: true, activePolicy: name });
      } catch (err: any) {
        this.json(res, { error: err.message }, 404);
      }
      return;
    }

    if (req.method === "DELETE" && url.startsWith("/api/policies/")) {
      const name = url.split("/").pop()!;
      const ok = this.policyManager.removePolicy(name);
      this.json(res, { ok }, ok ? 200 : 404);
      return;
    }

    if (req.method === "POST" && url === "/api/policies/export") {
      const exported = this.policyManager.exportPolicies();
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Content-Disposition": 'attachment; filename="carapace-policies.json"',
      });
      res.end(exported);
      return;
    }

    if (req.method === "POST" && url === "/api/policies/import") {
      this.readBody(req, (body) => {
        try {
          const count = this.policyManager.importPolicies(body);
          this.json(res, { ok: true, imported: count });
        } catch {
          this.json(res, { error: "Invalid import JSON" }, 400);
        }
      });
      return;
    }

    // 404
    this.json(res, { error: "Not found" }, 404);
  }

  private json(res: ServerResponse, data: unknown, status = 200): void {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(data));
  }

  private readBody(req: IncomingMessage, cb: (body: string) => void, res?: ServerResponse): void {
    const MAX_BODY = 1_048_576; // 1 MB
    let body = "";
    let exceeded = false;
    req.on("data", (chunk: Buffer) => {
      body += chunk.toString();
      if (body.length > MAX_BODY) {
        exceeded = true;
        req.destroy();
      }
    });
    req.on("end", () => {
      if (exceeded) {
        if (res) {
          res.writeHead(413, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Request body too large" }));
        }
        return;
      }
      cb(body);
    });
    req.on("error", () => {
      if (exceeded && res) {
        res.writeHead(413, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Request body too large" }));
      }
    });
  }
}

// ── 内嵌 Dashboard HTML ──

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Carapace Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f1117;color:#e1e4e8;min-height:100vh}
.header{background:#161b22;border-bottom:1px solid #30363d;padding:16px 24px;display:flex;align-items:center;gap:12px}
.header h1{font-size:20px;font-weight:600}
.header .badge{background:#238636;color:#fff;padding:2px 8px;border-radius:12px;font-size:12px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px;padding:24px}
.card{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px}
.card .label{color:#8b949e;font-size:13px;margin-bottom:4px}
.card .value{font-size:28px;font-weight:700}
.card .value.critical{color:#f85149}
.card .value.high{color:#d29922}
.card .value.medium{color:#58a6ff}
.card .value.ok{color:#3fb950}
.events{padding:0 24px 24px}
.events h2{font-size:16px;margin-bottom:12px;color:#8b949e}
.event-list{display:flex;flex-direction:column;gap:8px;max-height:500px;overflow-y:auto}
.event{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;display:flex;gap:12px;align-items:center}
.event .sev{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.event .sev.critical{background:#f85149}
.event .sev.high{background:#d29922}
.event .sev.medium{background:#58a6ff}
.event .sev.low{background:#3fb950}
.event .sev.info{background:#8b949e}
.event .meta{flex:1;min-width:0}
.event .title{font-size:14px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.event .sub{font-size:12px;color:#8b949e;margin-top:2px}
.event .action{font-size:11px;padding:2px 6px;border-radius:4px;font-weight:600}
.event .action.blocked{background:#f8514920;color:#f85149}
.event .action.alert{background:#58a6ff20;color:#58a6ff}
.empty{text-align:center;color:#8b949e;padding:40px}
</style>
</head>
<body>
<div class="header">
<span style="font-size:24px">🛡️</span>
<h1>Carapace Dashboard</h1>
<span class="badge">LIVE</span>
</div>
<div class="grid" id="stats"></div>
<div class="events">
<h2>Recent Events</h2>
<div class="event-list" id="events"><div class="empty">No events yet</div></div>
</div>
<script>
async function loadStats(){
  try{
    const r=await fetch('/api/stats');
    const s=await r.json();
    document.getElementById('stats').innerHTML=
      card('Total Events',s.total,s.total>0?'medium':'ok')+
      card('Critical',s.bySeverity.critical,'critical')+
      card('High',s.bySeverity.high,'high')+
      card('Blocked',s.blockedCount,s.blockedCount>0?'critical':'ok');
  }catch{}
}
async function loadEvents(){
  try{
    const r=await fetch('/api/events?limit=50');
    const events=await r.json();
    const el=document.getElementById('events');
    if(!events.length){el.innerHTML='<div class="empty">No events yet</div>';return}
    el.innerHTML=events.map(e=>eventRow(e)).join('');
  }catch{}
}
function card(label,value,cls){
  return '<div class="card"><div class="label">'+label+'</div><div class="value '+cls+'">'+value+'</div></div>';
}
function eventRow(e){
  const t=new Date(e.timestamp).toLocaleTimeString();
  return '<div class="event"><div class="sev '+esc(e.severity)+'"></div><div class="meta"><div class="title">'+esc(e.title)+'</div><div class="sub">'+esc(t)+' · '+esc(e.ruleName||'')+' · '+esc(e.toolName||'')+'</div></div><span class="action '+esc(e.action)+'">'+esc(e.action||'').toUpperCase()+'</span></div>';
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;')}
loadStats();loadEvents();
const es=new EventSource('/api/events/stream');
es.onmessage=function(e){
  try{
    const ev=JSON.parse(e.data);
    const el=document.getElementById('events');
    const empty=el.querySelector('.empty');
    if(empty)empty.remove();
    el.insertAdjacentHTML('afterbegin',eventRow(ev));
    loadStats();
  }catch{}
};
setInterval(loadStats,10000);
</script>
</body>
</html>`;
