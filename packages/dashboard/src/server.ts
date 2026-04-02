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
import { timingSafeEqual } from "node:crypto";
import type { SecurityEvent, AlertSink, AlertPayload } from "@carapace/core";
import { EventStore, type EventQuery } from "./event-store.js";
import { PolicyManager, type PolicyDefinition } from "./policy.js";

export interface DashboardConfig {
  /** HTTP 端口 (default: 9877) */
  port?: number;
  /** 绑定地址 (default: 127.0.0.1) */
  host?: string;
  /** CORS 来源 (default: same-origin, set to "*" for development) */
  corsOrigin?: string;
  /** 最大存储事件数 (default: 10000) */
  maxEvents?: number;
  /** API token for mutation endpoints (POST/PUT/DELETE). When set, requests
   *  must include `Authorization: Bearer <token>`. Read-only GET endpoints
   *  remain open so the embedded dashboard UI works without auth. */
  apiToken?: string;
}

export class DashboardServer {
  private store: EventStore;
  private policyManager: PolicyManager;
  private config: DashboardConfig;
  private server: ReturnType<typeof createServer> | null = null;
  private sseClients: Set<ServerResponse> = new Set();
  private sseHeartbeats: Map<ServerResponse, ReturnType<typeof setInterval>> = new Map();

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
    // Collect failed clients first to avoid modifying the Set during iteration
    const failed: ServerResponse[] = [];
    for (const client of this.sseClients) {
      try {
        // Sanitize event ID to prevent SSE frame injection via newlines
        const safeId = String(event.id).replace(/[\r\n]/g, "");
        const ok = client.write(`id: ${safeId}\ndata: ${data}\n\n`);
        if (!ok) {
          // Buffer full — slow client, disconnect to prevent memory growth
          failed.push(client);
        }
      } catch {
        failed.push(client);
      }
    }
    for (const client of failed) this.cleanupSSEClient(client);
  }

  /**
   * 启动 HTTP 服务
   */
  async start(): Promise<void> {
    if (this.server) throw new Error("Server already started — call stop() first");
    const port = this.config.port ?? 9877;
    const host = this.config.host ?? "127.0.0.1";
    const cors = this.config.corsOrigin;

    this.server = createServer(
      (req: IncomingMessage, res: ServerResponse) => {
        // Security headers
        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("X-Frame-Options", "DENY");
        res.setHeader("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'");

        if (cors) {
          res.setHeader("Access-Control-Allow-Origin", cors);
          res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
          res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        }

        if (req.method === "OPTIONS") {
          res.writeHead(204);
          res.end();
          return;
        }

        const url = req.url ?? "/";
        this.route(req, res, url);
      }
    );

    // Set HTTP timeouts to prevent slow-loris style attacks
    this.server.requestTimeout = 30_000;
    this.server.headersTimeout = 10_000;
    this.server.keepAliveTimeout = 5_000;

    return new Promise((resolve, reject) => {
      const onError = (err: Error) => reject(err);
      this.server!.on("error", onError);
      this.server!.listen(port, host, () => {
        this.server!.removeListener("error", onError);
        this.server!.on("error", (err: Error) => {
          process.stderr.write(`[carapace/dashboard] server error: ${err.message}\n`);
        });
        resolve();
      });
    });
  }

  /**
   * 获取当前监听端口（服务器启动后可用，端口 0 时获取实际分配端口）
   */
  getPort(): number {
    if (this.server) {
      const addr = this.server.address();
      if (addr && typeof addr === "object") {
        return addr.port;
      }
    }
    return this.config.port ?? 9877;
  }

  private cleanupSSEClient(res: ServerResponse): void {
    const heartbeat = this.sseHeartbeats.get(res);
    if (heartbeat) {
      clearInterval(heartbeat);
      this.sseHeartbeats.delete(res);
    }
    this.sseClients.delete(res);
    try { if (!res.writableEnded) res.end(); } catch { /* already closed */ }
  }

  /**
   * 停止 HTTP 服务
   */
  async stop(): Promise<void> {
    // Close SSE connections
    for (const res of this.sseClients) {
      try { res.end(); } catch { /* already closed */ }
    }
    this.sseClients.clear();

    // Explicitly clear all heartbeat intervals
    for (const heartbeat of this.sseHeartbeats.values()) {
      clearInterval(heartbeat);
    }
    this.sseHeartbeats.clear();

    if (!this.server) return;
    const srv = this.server;
    this.server = null;
    if (!srv.listening) return;

    return new Promise<void>((resolve) => {
      srv.close(() => resolve());
      srv.closeAllConnections?.();
    });
  }

  /**
   * Check Bearer token for mutation endpoints. Returns true if authorized.
   * When no apiToken is configured, all requests are allowed (backwards-compatible).
   */
  private requireAuth(req: IncomingMessage, res: ServerResponse): boolean {
    const token = this.config.apiToken;
    if (!token) return true; // no auth configured
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      this.json(res, { error: "Unauthorized" }, 401);
      return false;
    }
    const provided = authHeader.slice(7);
    // Constant-time comparison to prevent timing attacks
    const a = Buffer.from(token, "utf-8");
    const b = Buffer.from(provided, "utf-8");
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      this.json(res, { error: "Unauthorized" }, 401);
      return false;
    }
    return true;
  }

  private route(req: IncomingMessage, res: ServerResponse, url: string): void {
    const urlPath = url.split("?")[0];

    // ── Dashboard UI ──
    if (req.method === "GET" && (urlPath === "/" || urlPath === "/dashboard")) {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(DASHBOARD_HTML);
      return;
    }

    // ── SSE endpoint ──
    if (req.method === "GET" && urlPath === "/api/events/stream") {
      // Limit concurrent SSE connections to prevent resource exhaustion
      const MAX_SSE_CLIENTS = 50;
      if (this.sseClients.size >= MAX_SSE_CLIENTS) {
        this.json(res, { error: "Too many SSE connections" }, 429);
        return;
      }
      res.writeHead(200, {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        Connection: "keep-alive",
      });
      this.sseClients.add(res);
      // 定期发送心跳，帮助检测死连接
      const heartbeat = setInterval(() => {
        try {
          if (res.destroyed) {
            this.cleanupSSEClient(res);
            return;
          }
          res.write(":heartbeat\n\n");
        } catch {
          this.cleanupSSEClient(res);
        }
      }, 30_000);
      this.sseHeartbeats.set(res, heartbeat);
      req.on("close", () => this.cleanupSSEClient(res));
      req.on("error", () => this.cleanupSSEClient(res));
      return;
    }

    // ── API Routes ──
    if (req.method === "GET" && urlPath === "/api/health") {
      this.json(res, { status: "ok" });
      return;
    }

    if (req.method === "GET" && urlPath === "/api/events") {
      const params = new URL(url, "http://localhost").searchParams;
      const query: EventQuery = {};
      const VALID_CATEGORIES = new Set(["exec_danger", "path_violation", "network_suspect", "rate_anomaly", "baseline_drift", "prompt_injection", "data_exfil"]);
      const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
      const cat = params.get("category");
      if (cat && VALID_CATEGORIES.has(cat)) query.category = cat as EventQuery["category"];
      const sev = params.get("severity");
      if (sev && VALID_SEVERITIES.has(sev)) query.severity = sev as EventQuery["severity"];
      const ruleNameVal = params.get("ruleName");
      if (ruleNameVal && ruleNameVal.length <= 200) query.ruleName = ruleNameVal;
      const sessionIdVal = params.get("sessionId");
      if (sessionIdVal && sessionIdVal.length <= 200) query.sessionId = sessionIdVal;
      const skillNameVal = params.get("skillName");
      if (skillNameVal && skillNameVal.length <= 200) query.skillName = skillNameVal;
      const sinceVal = parseInt(params.get("since") ?? "", 10);
      if (!isNaN(sinceVal)) query.since = sinceVal;
      const limitVal = parseInt(params.get("limit") ?? "", 10);
      if (!isNaN(limitVal) && limitVal > 0) query.limit = Math.min(limitVal, 10000);
      const offsetVal = parseInt(params.get("offset") ?? "", 10);
      if (!isNaN(offsetVal) && offsetVal >= 0) query.offset = Math.min(offsetVal, 100000);

      const events = this.store.query(query);
      this.json(res, events);
      return;
    }

    if (req.method === "GET" && urlPath === "/api/stats") {
      const params = new URL(url, "http://localhost").searchParams;
      const sinceVal = parseInt(params.get("since") ?? "", 10);
      const since = isNaN(sinceVal) ? undefined : sinceVal;
      const stats = this.store.getStats(since);
      this.json(res, stats);
      return;
    }

    if (req.method === "GET" && urlPath === "/api/timeseries") {
      const params = new URL(url, "http://localhost").searchParams;
      const bucketVal = parseInt(params.get("bucket") ?? "60000", 10);
      const bucketMs = isNaN(bucketVal) || bucketVal < 1000 ? 60000 : Math.min(bucketVal, 86400000);
      const sinceVal = parseInt(params.get("since") ?? "", 10);
      const since = isNaN(sinceVal) ? undefined : sinceVal;
      const ts = this.store.timeSeries(bucketMs, since);
      this.json(res, ts);
      return;
    }

    // ── Policy API ──
    if (req.method === "GET" && urlPath === "/api/policies") {
      this.json(res, this.policyManager.listPolicies());
      return;
    }

    if (req.method === "GET" && urlPath === "/api/policies/active") {
      const active = this.policyManager.resolveActivePolicy();
      this.json(res, active ?? { name: null });
      return;
    }

    if (req.method === "POST" && urlPath === "/api/policies") {
      if (!this.requireAuth(req, res)) return;
      if (req.headers["content-type"]?.split(";")[0]?.trim() !== "application/json") {
        this.json(res, { error: "Content-Type must be application/json" }, 415);
        return;
      }
      this.readBody(req, (body) => {
        try {
          const policy = JSON.parse(body) as PolicyDefinition;
          if (!policy.name || typeof policy.name !== "string") {
            this.json(res, { error: "Missing required field: name" }, 400);
            return;
          }
          policy.createdAt = policy.createdAt ?? Date.now();
          policy.updatedAt = Date.now();
          try {
            this.policyManager.addPolicy(policy);
          } catch (addErr) {
            this.json(res, { error: addErr instanceof Error ? addErr.message : "Invalid policy" }, 400);
            return;
          }
          this.json(res, { ok: true, name: policy.name }, 201);
        } catch {
          this.json(res, { error: "Invalid policy JSON" }, 400);
        }
      }, res);
      return;
    }

    if (req.method === "PUT" && urlPath.startsWith("/api/policies/active/")) {
      if (!this.requireAuth(req, res)) return;
      const rawName = urlPath.slice("/api/policies/active/".length);
      if (!rawName) { this.json(res, { error: "Missing policy name" }, 400); return; }
      let name: string;
      try { name = decodeURIComponent(rawName); } catch { this.json(res, { error: "Invalid policy name encoding" }, 400); return; }
      try {
        this.policyManager.setActivePolicy(name);
        this.json(res, { ok: true, activePolicy: name });
      } catch (err) {
        process.stderr.write(`[CARAPACE] policy error: ${err instanceof Error ? err.message : String(err)}\n`);
        this.json(res, { error: "Policy not found" }, 404);
      }
      return;
    }

    if (req.method === "DELETE" && urlPath.startsWith("/api/policies/")) {
      if (!this.requireAuth(req, res)) return;
      const rawName = urlPath.slice("/api/policies/".length);
      // Reject sub-paths (e.g., /api/policies/active/foo) and reserved endpoints
      if (!rawName || rawName.includes("/") || rawName === "export" || rawName === "import" || rawName === "active") {
        this.json(res, { error: "Missing or invalid policy name" }, 400);
        return;
      }
      let name: string;
      try { name = decodeURIComponent(rawName); } catch { this.json(res, { error: "Invalid policy name encoding" }, 400); return; }
      const ok = this.policyManager.removePolicy(name);
      this.json(res, { ok }, ok ? 200 : 404);
      return;
    }

    if (req.method === "POST" && urlPath === "/api/policies/export") {
      if (!this.requireAuth(req, res)) return;
      const exported = this.policyManager.exportPolicies();
      res.writeHead(200, {
        "Content-Type": "application/json",
        "Content-Disposition": 'attachment; filename="carapace-policies.json"',
      });
      res.end(exported);
      return;
    }

    if (req.method === "POST" && urlPath === "/api/policies/import") {
      if (!this.requireAuth(req, res)) return;
      if (req.headers["content-type"]?.split(";")[0]?.trim() !== "application/json") {
        this.json(res, { error: "Content-Type must be application/json" }, 415);
        return;
      }
      this.readBody(req, (body) => {
        try {
          const result = this.policyManager.importPolicies(body);
          this.json(res, { ok: true, ...result });
        } catch {
          this.json(res, { error: "Invalid import JSON" }, 400);
        }
      }, res);
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
    const chunks: Buffer[] = [];
    let totalSize = 0;
    let exceeded = false;
    let responded = false;
    req.on("data", (chunk: Buffer) => {
      totalSize += chunk.length;
      if (totalSize > MAX_BODY) {
        exceeded = true;
        req.destroy();
        send413();
        return;
      }
      chunks.push(chunk);
    });
    const send413 = () => {
      if (responded || !res) return;
      responded = true;
      res.writeHead(413, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Request body too large" }));
    };
    req.on("end", () => {
      if (exceeded) { send413(); return; }
      try {
        const body = Buffer.concat(chunks).toString("utf-8");
        cb(body);
      } catch {
        if (res && !responded) {
          responded = true;
          res.writeHead(500, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Internal server error" }));
        }
      }
    });
    req.on("error", () => {
      if (exceeded) { send413(); return; }
      if (!responded && res) {
        responded = true;
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Request error" }));
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
  }catch(e){console.error('Failed to load stats:',e)}
}
async function loadEvents(){
  try{
    const r=await fetch('/api/events?limit=50');
    const events=await r.json();
    const el=document.getElementById('events');
    if(!events.length){el.innerHTML='<div class="empty">No events yet</div>';return}
    el.innerHTML=events.map(e=>eventRow(e)).join('');
  }catch(e){console.error('Failed to load events:',e)}
}
function card(label,value,cls){
  var validCls=['critical','high','medium','ok','blocked','rules','sessions','events'];
  var safeCls=validCls.indexOf(cls)>=0?cls:'';
  return '<div class="card"><div class="label">'+esc(label)+'</div><div class="value '+safeCls+'">'+esc(String(value))+'</div></div>';
}
function sevClass(s){var valid=['info','low','medium','high','critical'];return valid.indexOf(s)>=0?s:'info'}
function actClass(s){var valid=['alert','blocked','log'];return valid.indexOf(s)>=0?s:'alert'}
function eventRow(e){
  const t=new Date(e.timestamp).toLocaleTimeString();
  return '<div class="event"><div class="sev '+sevClass(e.severity)+'"></div><div class="meta"><div class="title">'+esc(e.title)+'</div><div class="sub">'+esc(t)+' · '+esc(e.ruleName||'')+' · '+esc(e.toolName||'')+'</div></div><span class="action '+actClass(e.action)+'">'+esc(e.action||'').toUpperCase()+'</span></div>';
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;')}
loadStats();loadEvents();
function connectSSE(){
  var es=new EventSource('/api/events/stream');
  es.onmessage=function(e){
    try{
      var ev=JSON.parse(e.data);
      var el=document.getElementById('events');
      var empty=el.querySelector('.empty');
      if(empty)empty.remove();
      var tmp=document.createElement('div');
      tmp.innerHTML=eventRow(ev);
      if(tmp.firstChild)el.insertBefore(tmp.firstChild,el.firstChild);
      while(el.children.length>200)el.removeChild(el.lastChild);
      loadStats();
    }catch(err){console.error('SSE parse error:',err)}
  };
  es.onerror=function(){es.close();setTimeout(connectSSE,5000)};
}
connectSSE();
setInterval(loadStats,10000);
</script>
</body>
</html>`;
