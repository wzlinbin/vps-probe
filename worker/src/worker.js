// vps-probe Worker: 面板 + 上报 API
// 安全要点:
// - 面板需密码登录(Session Cookie, HttpOnly/Secure/SameSite, KV 存储, 7 天过期, 登录限流)
// - 上报需 Bearer token(与 secret 做 SHA-256 后定长比较), 严格 schema 校验, 限流 10 秒/节点
// - 所有响应带安全头, API 与页面均为 no-store; 不记录、不返回任何 secret
// - KV 只存节点快照/首次上线时间/节点元信息, 不存 token

const SESSION_TTL = 7 * 86400; // 秒
const PUSH_MIN_INTERVAL = 10; // 秒/节点
const ONLINE_THRESHOLD = 120; // 秒内有上报算在线
const MAX_BODY = 65536;
const NODE_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const ROUTES = new Set(["163", "CN2", "9929", "CMIN2", "4837", "9808", "未知"]);

function secHeaders() {
  return {
    "content-security-policy":
      "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
  };
}

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", ...secHeaders(), ...extraHeaders },
  });
}

function html(body, status = 200) {
  return new Response(body, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", ...secHeaders() },
  });
}

async function sha256Hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// 定长比较, 避免时序侧信道
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function randomHex(bytes) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return [...arr].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function getCookie(request, name) {
  const c = request.headers.get("cookie") || "";
  for (const part of c.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

async function getSession(request, env) {
  const token = getCookie(request, "probe_session");
  if (!token || !/^[0-9a-f]{64}$/.test(token)) return false;
  const v = await env.PROBE_KV.get("session:" + token);
  return v !== null;
}

function clientIP(request) {
  return request.headers.get("cf-connecting-ip") || "unknown";
}

// ---------- 上报校验 ----------

function isNum(v, min, max) {
  return typeof v === "number" && Number.isFinite(v) && v >= min && v <= max;
}

function validatePing(p) {
  if (p === null || typeof p !== "object" || Array.isArray(p)) return "ping 格式错误";
  for (const k of ["ct", "cu", "cm"]) {
    const r = p[k];
    if (r === undefined) return "ping 缺少 " + k;
    if (r !== null) {
      if (typeof r !== "object" || Array.isArray(r)) return "ping." + k + " 格式错误";
      if (r.avg !== null && !isNum(r.avg, 0, 10000)) return "ping." + k + ".avg 越界";
      if (r.loss !== null && !isNum(r.loss, 0, 100)) return "ping." + k + ".loss 越界";
      for (const key of Object.keys(r)) if (key !== "avg" && key !== "loss") return "ping." + k + " 含未知字段";
    }
  }
  for (const key of Object.keys(p)) if (!["ct", "cu", "cm"].includes(key)) return "ping 含未知字段";
  return null;
}

function validateRoute(r) {
  if (r === null || typeof r !== "object" || Array.isArray(r)) return "route 格式错误";
  for (const k of ["ct", "cu", "cm"]) {
    const v = r[k];
    if (v === undefined) return "route 缺少 " + k;
    if (v === null) continue;
    // 兼容旧版 agent 的扁平格式: route.ct 直接是 "163" 这样的字符串
    if (typeof v === "string") {
      if (!ROUTES.has(v)) return "route." + k + " 非法";
      continue;
    }
    if (typeof v !== "object" || Array.isArray(v)) return "route." + k + " 格式错误";
    for (const city of ["sh", "gz", "bj"]) {
      const cv = v[city];
      if (cv === undefined) return "route." + k + " 缺少 " + city;
      if (cv !== null && (typeof cv !== "string" || !ROUTES.has(cv))) return "route." + k + "." + city + " 非法";
    }
    for (const key of Object.keys(v)) if (!["sh", "gz", "bj"].includes(key)) return "route." + k + " 含未知字段";
  }
  for (const key of Object.keys(r)) if (!["ct", "cu", "cm"].includes(key)) return "route 含未知字段";
  return null;
}

function validateReport(d) {
  if (d === null || typeof d !== "object" || Array.isArray(d)) return "body 必须是 JSON 对象";
  const allowed = new Set(["node", "name", "carrier", "return_routes", "ts", "hostname", "uptime", "cpu", "load", "mem_total", "mem_used",
    "disk_total", "disk_used", "net_rx", "net_tx", "net_rx_rate", "net_tx_rate", "ping", "route"]);
  for (const k of Object.keys(d)) if (!allowed.has(k)) return "未知字段: " + k;
  if (typeof d.node !== "string" || !NODE_RE.test(d.node)) return "node 非法";
  if (d.carrier !== undefined) {
    if (!["ct", "cu", "cm"].includes(d.carrier)) return "carrier 非法";
  }
  if (d.return_routes !== undefined) {
    if (d.carrier === undefined) return "回程上报需 carrier";
    if (d.return_routes === null || typeof d.return_routes !== "object" || Array.isArray(d.return_routes)) return "return_routes 格式错误";
    for (const [k, v] of Object.entries(d.return_routes)) {
      if (!NODE_RE.test(k)) return "return_routes 目标非法";
      if (!["163", "9929", "CMIN2", "4837"].includes(v)) return "return_routes 线路非法";
    }
  }
  if (d.name !== undefined) {
    if (typeof d.name !== "string" || d.name.length < 1 || d.name.length > 32 || /[\x00-\x1f\x7f]/.test(d.name)) return "name 非法";
  }
  if (!isNum(d.ts, 0, 4102444800)) return "ts 非法";
  if (Math.abs(Date.now() / 1000 - d.ts) > 3600) return "ts 与服务器时间相差超过 1 小时";
  if (typeof d.hostname !== "string" || d.hostname.length > 64) return "hostname 非法";
  if (!isNum(d.uptime, 0, 2147483647)) return "uptime 非法";
  if (!isNum(d.cpu, 0, 100)) return "cpu 越界";
  if (!Array.isArray(d.load) || d.load.length !== 3 || !d.load.every((v) => isNum(v, 0, 10000))) return "load 非法";
  if (!isNum(d.mem_total, 0, Number.MAX_SAFE_INTEGER) || !isNum(d.mem_used, 0, Number.MAX_SAFE_INTEGER) || d.mem_used > d.mem_total) return "内存数据非法";
  if (!isNum(d.disk_total, 0, Number.MAX_SAFE_INTEGER) || !isNum(d.disk_used, 0, Number.MAX_SAFE_INTEGER) || d.disk_used > d.disk_total) return "硬盘数据非法";
  for (const k of ["net_rx", "net_tx", "net_rx_rate", "net_tx_rate"]) {
    if (!isNum(d[k], 0, Number.MAX_SAFE_INTEGER)) return k + " 非法";
  }
  const pe = validatePing(d.ping);
  if (pe) return pe;
  const re = validateRoute(d.route);
  if (re) return re;
  return null;
}

// ---------- 路由 ----------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === "/health") return json({ ok: true });

    if (path === "/api/push" && request.method === "POST") return handlePush(request, env);
    if (path === "/api/login" && request.method === "POST") return handleLogin(request, env);
    if (path === "/api/logout" && request.method === "POST") return handleLogout(request, env);
    if (path === "/api/status" && request.method === "GET") {
      if (!(await getSession(request, env))) return json({ error: "未登录" }, 401);
      return handleStatus(env);
    }
    if (path === "/api/meta" && request.method === "POST") {
      if (!(await getSession(request, env))) return json({ error: "未登录" }, 401);
      return handleMeta(request, env);
    }
    if (path === "/" && request.method === "GET") {
      if (await getSession(request, env)) return html(DASHBOARD_HTML);
      return html(LOGIN_HTML);
    }
    return json({ error: "not found" }, 404);
  },
};

async function handlePush(request, env) {
  const auth = request.headers.get("authorization") || "";
  const m = /^Bearer\s+(\S+)$/.exec(auth);
  if (!m) return json({ error: "unauthorized" }, 401);
  const tokenHash = await sha256Hex(m[1]);
  const expectHash = await sha256Hex(env.AGENT_TOKEN || "");
  if (!timingSafeEqual(tokenHash, expectHash)) return json({ error: "unauthorized" }, 401);

  const len = Number(request.headers.get("content-length") || "0");
  if (len > MAX_BODY) return json({ error: "body 太大" }, 413);
  let text;
  try {
    text = await request.text();
  } catch {
    return json({ error: "读取 body 失败" }, 400);
  }
  if (text.length > MAX_BODY) return json({ error: "body 太大" }, 413);
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return json({ error: "JSON 解析失败" }, 400);
  }
  const err = validateReport(data);
  if (err) return json({ error: err }, 400);

  const now = Math.floor(Date.now() / 1000);
  const rlKey = "rl:" + data.node;
  const last = await env.PROBE_KV.get(rlKey);
  if (last && now - Number(last) < PUSH_MIN_INTERVAL) {
    return json({ error: "上报过于频繁" }, 429);
  }
  await env.PROBE_KV.put(rlKey, String(now), { expirationTtl: 60 });
  await env.PROBE_KV.put("node:" + data.node + ":latest", JSON.stringify({ receivedAt: now, data }), { expirationTtl: 7 * 86400 });
  const first = await env.PROBE_KV.get("node:" + data.node + ":first_seen");
  if (first === null) await env.PROBE_KV.put("node:" + data.node + ":first_seen", String(now));
  // 回程探测结果: 按目标节点 + 探测方运营商存, 1 小时过期, 状态接口只取 10 分钟内的
  if (data.carrier && data.return_routes) {
    for (const [target, label] of Object.entries(data.return_routes)) {
      await env.PROBE_KV.put("return:" + target + ":" + data.carrier, JSON.stringify({ route: label, ts: now }), { expirationTtl: 3600 });
    }
  }
  return json({ ok: true });
}

async function handleLogin(request, env) {
  const ip = clientIP(request);
  const key = "login:" + ip;
  const count = Number((await env.PROBE_KV.get(key)) || "0");
  if (count >= 5) return json({ error: "尝试过多, 请 5 分钟后再试" }, 429);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "JSON 解析失败" }, 400);
  }
  const pw = typeof body.password === "string" ? body.password : "";
  const ok = timingSafeEqual(await sha256Hex(pw), await sha256Hex(env.DASHBOARD_PASSWORD || ""));
  if (!ok) {
    await env.PROBE_KV.put(key, String(count + 1), { expirationTtl: 300 });
    return json({ error: "密码错误" }, 401);
  }
  await env.PROBE_KV.delete(key);
  const token = randomHex(32);
  await env.PROBE_KV.put("session:" + token, "1", { expirationTtl: SESSION_TTL });
  return json(
    { ok: true },
    200,
    { "set-cookie": "probe_session=" + token + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=" + SESSION_TTL },
  );
}

async function handleLogout(request, env) {
  const token = getCookie(request, "probe_session");
  if (token) await env.PROBE_KV.delete("session:" + token);
  return json({ ok: true }, 200, { "set-cookie": "probe_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0" });
}

async function handleStatus(env) {
  const list = await env.PROBE_KV.list({ prefix: "node:" });
  const now = Math.floor(Date.now() / 1000);
  const nodes = [];
  for (const k of list.keys) {
    if (!k.name.endsWith(":latest")) continue;
    const id = k.name.slice(5, -7);
    const latest = await env.PROBE_KV.get(k.name);
    if (!latest) continue;
    const parsed = JSON.parse(latest);
    const firstSeen = Number((await env.PROBE_KV.get("node:" + id + ":first_seen")) || parsed.receivedAt);
    let meta = null;
    const metaRaw = await env.PROBE_KV.get("node:" + id + ":meta");
    if (metaRaw) { try { meta = JSON.parse(metaRaw); } catch { meta = null; } }
    // 回程: 取国内探测节点上报的各运营商线路, 只取 10 分钟内的
    const retRaw = await Promise.all(["ct", "cu", "cm"].map((c) => env.PROBE_KV.get("return:" + id + ":" + c)));
    const ret = {};
    ["ct", "cu", "cm"].forEach((c, i) => {
      let v = null;
      if (retRaw[i]) { try { const p = JSON.parse(retRaw[i]); if (p && p.route && now - p.ts < 600) v = p.route; } catch { /* 忽略损坏记录 */ } }
      ret[c] = v;
    });
    nodes.push({
      id,
      online: now - parsed.receivedAt < ONLINE_THRESHOLD,
      lastSeen: parsed.receivedAt,
      firstSeen,
      data: parsed.data,
      meta,
      ret,
    });
  }
  nodes.sort((a, b) => (a.id < b.id ? -1 : 1));
  return json({ nodes, now });
}

async function handleMeta(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "JSON 解析失败" }, 400);
  }
  if (typeof body.node !== "string" || !NODE_RE.test(body.node)) return json({ error: "node 非法" }, 400);
  const meta = {};
  if (body.name !== undefined && body.name !== null) {
    if (typeof body.name !== "string" || body.name.length > 32 || /[\x00-\x1f\x7f]/.test(body.name)) return json({ error: "name 非法" }, 400);
    meta.name = body.name;
  }
  if (body.quotaGB !== undefined && body.quotaGB !== null) {
    if (!isNum(body.quotaGB, 0, 1000000)) return json({ error: "quotaGB 非法" }, 400);
    meta.quotaGB = body.quotaGB;
  }
  if (body.expiresAt !== undefined && body.expiresAt !== null) {
    if (typeof body.expiresAt !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(body.expiresAt) || Number.isNaN(Date.parse(body.expiresAt + "T00:00:00Z"))) {
      return json({ error: "expiresAt 须为 YYYY-MM-DD" }, 400);
    }
    meta.expiresAt = body.expiresAt;
  }
  if (body.price !== undefined && body.price !== null) {
    if (typeof body.price !== "string" || body.price.length > 32) return json({ error: "price 非法" }, 400);
    meta.price = body.price;
  }
  await env.PROBE_KV.put("node:" + body.node + ":meta", JSON.stringify(meta));
  return json({ ok: true });
}

// ---------- 页面 ----------

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>探针 · 登录</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#eef0f4;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;color:#1f2430}
.card{background:#fff;border-radius:18px;box-shadow:0 8px 30px rgba(30,40,70,.10);padding:36px 32px;width:min(92vw,360px)}
h1{font-size:20px;margin:0 0 6px}p{color:#8a90a0;font-size:13px;margin:0 0 22px}
input{width:100%;padding:12px 14px;border:1px solid #d8dce6;border-radius:10px;font-size:15px;outline:none}
input:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.15)}
button{width:100%;margin-top:14px;padding:12px;border:0;border-radius:10px;background:#1f2430;color:#fff;font-size:15px;cursor:pointer}
button:hover{background:#374151}.err{color:#dc2626;font-size:13px;min-height:18px;margin-top:10px}
</style></head><body><div class="card"><h1>探针</h1><p>请输入面板密码</p>
<input id="pw" type="password" placeholder="密码" autocomplete="current-password">
<button id="btn">登录</button><div class="err" id="err"></div></div>
<script>
var pw=document.getElementById('pw'),err=document.getElementById('err');
function login(){fetch('/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:pw.value})}).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j}})}).then(function(x){if(x.ok){location.reload()}else{err.textContent=x.j.error||'登录失败'}}).catch(function(){err.textContent='网络错误'})}
document.getElementById('btn').addEventListener('click',login);
pw.addEventListener('keydown',function(e){if(e.key==='Enter')login()});pw.focus();
</script></body></html>`;

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>探针</title><style>
*{box-sizing:border-box}body{margin:0;background:#eef0f4;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;color:#1f2430}
.wrap{max-width:760px;margin:0 auto;padding:24px 16px 48px}
.top{display:flex;justify-content:space-between;align-items:center;margin:4px 4px 16px}
.top h1{font-size:20px;margin:0}.top .sub{color:#8a90a0;font-size:12px;margin-top:2px}
.logout{background:none;border:1px solid #d8dce6;border-radius:8px;padding:6px 12px;font-size:13px;color:#5b6474;cursor:pointer}
.card{background:#fff;border-radius:18px;box-shadow:0 8px 30px rgba(30,40,70,.08);padding:22px;margin-bottom:16px}
.nodehead{display:flex;justify-content:space-between;align-items:baseline}
.nodehead h2{font-size:19px;margin:0}.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:1px}
.dot.on{background:#22c55e;box-shadow:0 0 0 3px rgba(34,197,94,.2)}.dot.off{background:#cbd5e1}
.nodehead .meta{color:#8a90a0;font-size:13px}
.gauges{display:grid;grid-template-columns:repeat(3,1fr);gap:14px 20px;margin-top:18px}
.tile{text-align:center}.tile .lab{font-size:13px;color:#5b6474;display:flex;align-items:center;justify-content:center;gap:6px}
.tile .big{font-size:22px;font-weight:650;margin-top:4px}
.tile .small{font-size:12px;color:#8a90a0;margin-top:2px}
.gauge{width:150px;max-width:100%;display:block;margin:0 auto}
.traffic{margin-top:16px;padding:14px 16px;background:#f8f9fb;border:1px solid #eef0f4;border-radius:12px;display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap}
.traffic .lab{font-size:13px;color:#5b6474}
.traffic .t-left{flex:1;min-width:220px}
.traffic .t-big{font-size:24px;font-weight:650;margin-top:2px}
.traffic .small{font-size:12px;color:#8a90a0;margin-top:2px}
.traffic .t-right{text-align:right;flex-shrink:0}
.traffic .t-rate{font-size:14px}
.qbar{height:8px;background:#e5e8ee;border-radius:99px;overflow:hidden;margin-top:10px}
.qbar i{display:block;height:100%;border-radius:99px}
.ping{margin-top:16px;padding-top:14px;border-top:1px solid #eef0f4}
.prow{display:grid;grid-template-columns:52px 70px 1fr 52px;align-items:center;gap:10px;padding:7px 0;font-size:14px}
.bar{height:8px;background:#eef0f4;border-radius:99px;overflow:hidden}.bar i{display:block;height:100%;border-radius:99px}
.ping .loss{color:#8a90a0;font-size:12px;text-align:right}
table{width:100%;border-collapse:collapse;margin-top:14px;font-size:14px}
th,td{padding:8px 4px;text-align:left;border-bottom:1px solid #eef0f4}
th{color:#8a90a0;font-weight:500;font-size:12px}
.route-tag{display:inline-block;padding:2px 10px;border-radius:99px;background:#fef3c7;color:#92400e;font-size:13px;margin:1px 4px 1px 0}
.route-tag.unknown{background:#f1f5f9;color:#64748b}
.note{color:#8a90a0;font-size:12px;margin-top:10px}
.metaform{margin-top:16px;padding-top:14px;border-top:1px solid #eef0f4;display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.metaform input{padding:8px 10px;border:1px solid #d8dce6;border-radius:8px;font-size:13px;width:120px}
.metaform button{padding:8px 14px;border:0;border-radius:8px;background:#1f2430;color:#fff;font-size:13px;cursor:pointer}
.metaform .saved{color:#16a34a;font-size:13px}
.empty{background:#fff;border-radius:18px;box-shadow:0 8px 30px rgba(30,40,70,.08);padding:40px 24px;text-align:center;color:#8a90a0}
@media(max-width:560px){.gauges{gap:8px}.prow{grid-template-columns:44px 62px 1fr 46px}}
</style></head><body><div class="wrap">
<div class="top"><div><h1>探针</h1><div class="sub" id="updated"></div></div><button class="logout" id="logout">退出</button></div>
<div id="list"></div>
</div>
<script>
var list=document.getElementById('list'),updated=document.getElementById('updated');
function esc(s){return String(s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function fmtBytes(b){if(b>=1073741824)return (b/1073741824).toFixed(1)+' GB';if(b>=1048576)return (b/1048576).toFixed(1)+' MB';if(b>=1024)return (b/1024).toFixed(1)+' KB';return b+' B'}
function fmtRate(b){if(b>=1048576)return (b/1048576).toFixed(2)+' MB/s';if(b>=1024)return (b/1024).toFixed(1)+' KB/s';return b+' B/s'}
function pct(a,b){if(!b)return 0;return Math.min(100,Math.round(a/b*1000)/10)}
function daysSince(ts){var d=Math.floor((Date.now()/1000-ts)/86400);return d<1?'不到 1 天':d+' 天'}
function timeAgo(ts){var s=Math.floor(Date.now()/1000-ts);if(s<60)return s+' 秒前';if(s<3600)return Math.floor(s/60)+' 分钟前';return Math.floor(s/3600)+' 小时前'}
function barColor(ms){if(ms==null)return '#cbd5e1';if(ms<120)return '#22c55e';if(ms<250)return '#eab308';return '#ef4444'}
function pingRow(name,r){var ms=r&&r.avg!=null?Math.round(r.avg):null;var loss=r&&r.loss!=null?r.loss:null;
 var w=ms==null?0:Math.min(100,ms/300*100);
 return '<div class="prow"><span>'+name+'</span><span>'+(ms==null?'—':ms+' ms')+'</span><span class="bar"><i style="width:'+w+'%;background:'+barColor(ms)+'"></i></span><span class="loss">'+(loss==null?'—':(Math.round(loss*10)/10)+'% 丢包')+'</span></div>'}
function routeTag(v){if(!v)return '<span class="route-tag unknown">未知</span>';if(v==='未知')return '<span class="route-tag unknown">未知</span>';return '<span class="route-tag">'+esc(v)+'</span>'}
function cityTags(r){
  if(typeof r === 'string') return routeTag(r);
  if(!r) return '<span class="route-tag unknown">未知</span>';
  var cities=[['sh','沪'],['gz','粤'],['bj','京']];
  var out='';
  cities.forEach(function(c){
    var v=r[c[0]];
    if(v==null) return;
    if(v==='未知') out+='<span class="route-tag unknown">'+c[1]+' 未知</span> ';
    else out+='<span class="route-tag">'+c[1]+' '+esc(v)+'</span> ';
  });
  return out==='' ? '<span class="route-tag unknown">未知</span>' : out.trim();
}
function retTag(v){if(!v)return '<span class="route-tag unknown">—</span>';return '<span class="route-tag">'+esc(v)+'</span>'}
// 圆盘指针仪表: 240 度表盘(左下 210 度经顶部到右下 -30 度), 指针指向数值, 颜色随阈值变
function polar(cx,cy,r,deg){var a=deg*Math.PI/180;return [cx+r*Math.cos(a),cy-r*Math.sin(a)]}
function arcD(cx,cy,r,a0,a1){var s=polar(cx,cy,r,a0),e=polar(cx,cy,r,a1);var large=(a0-a1)>180?1:0;return 'M '+s[0].toFixed(1)+' '+s[1].toFixed(1)+' A '+r+' '+r+' 0 '+large+' 1 '+e[0].toFixed(1)+' '+e[1].toFixed(1)}
function gaugeColor(v){if(v<60)return '#22c55e';if(v<85)return '#eab308';return '#ef4444'}
function gauge(v){
  var ang=210-v/100*240;
  var tip=polar(60,52,32,ang);
  var valArc=v<=0?'':('<path d="'+arcD(60,52,44,210,ang)+'" fill="none" stroke="'+gaugeColor(v)+'" stroke-width="8" stroke-linecap="round"/>');
  var p0=polar(60,52,54,210),p1=polar(60,52,54,-30);
  return '<svg viewBox="0 0 120 86" class="gauge">'
   +'<path d="'+arcD(60,52,44,210,-30)+'" fill="none" stroke="#eef0f4" stroke-width="8" stroke-linecap="round"/>'
   +valArc
   +'<line x1="60" y1="52" x2="'+tip[0].toFixed(1)+'" y2="'+tip[1].toFixed(1)+'" stroke="#1f2430" stroke-width="2" stroke-linecap="round"/>'
   +'<circle cx="60" cy="52" r="4" fill="#1f2430"/>'
   +'<text x="'+p0[0].toFixed(0)+'" y="'+(p0[1]+3).toFixed(0)+'" font-size="9" fill="#8a90a0" text-anchor="middle">0</text>'
   +'<text x="'+p1[0].toFixed(0)+'" y="'+(p1[1]+3).toFixed(0)+'" font-size="9" fill="#8a90a0" text-anchor="middle">100</text>'
   +'<text x="60" y="76" font-size="14" font-weight="700" fill="#1f2430" text-anchor="middle">'+v.toFixed(1)+'%</text>'
   +'</svg>';
}
function render(nodes,now){
 if(!nodes.length){list.innerHTML='<div class="empty">暂无节点<br><span style="font-size:13px">在 VPS 上安装 agent 并上报成功后,这里会显示数据。</span></div>';return}
 var h='';
 nodes.forEach(function(n){
  var d=n.data,m=n.meta||{};
  var memPct=pct(d.mem_used,d.mem_total),diskPct=pct(d.disk_used,d.disk_total);
  var traffic=d.net_rx+d.net_tx;
  var quotaPct=m.quotaGB?pct(traffic,m.quotaGB*1073741824):null;
  var remain='';
  if(m.expiresAt){var days=Math.ceil((new Date(m.expiresAt+'T00:00:00Z').getTime()-Date.now())/86400000);remain='剩余 '+days+' 天';}
  var displayName=(m.name&&m.name.length?m.name:(d.name&&d.name.length?d.name:n.id));
  var idSuffix=(displayName!==n.id)?' · '+esc(n.id):'';
  h+='<div class="card"><div class="nodehead"><h2><span class="dot '+(n.online?'on':'off')+'"></span>'+esc(displayName)+'</h2><span class="meta">'+(n.online?'在线':'离线')+' · 在线 '+daysSince(n.firstSeen)+idSuffix+(remain?' · '+remain:'')+(m.price?' · '+esc(m.price):'')+'</span></div>';
  h+='<div class="gauges">'
   +'<div class="tile"><div class="lab">CPU</div>'+gauge(d.cpu)+'<div class="small">'+d.load.map(function(x){return x.toFixed(2)}).join(', ')+'</div></div>'
   +'<div class="tile"><div class="lab">内存</div>'+gauge(memPct)+'<div class="small">'+fmtBytes(d.mem_used)+' / '+fmtBytes(d.mem_total)+'</div></div>'
   +'<div class="tile"><div class="lab">硬盘</div>'+gauge(diskPct)+'<div class="small">'+fmtBytes(d.disk_used)+' / '+fmtBytes(d.disk_total)+'</div></div>'
   +'</div>';
  h+='<div class="traffic"><div class="t-left"><div class="lab">流量</div><div class="t-big">'+fmtBytes(traffic)+'</div><div class="small">'+(m.quotaGB?('配额 '+m.quotaGB+' GB · 已用 '+quotaPct+'%'):'累计')+'</div>'+(quotaPct==null?'':'<div class="qbar"><i style="width:'+Math.min(quotaPct,100)+'%;background:'+gaugeColor(quotaPct)+'"></i></div>')+'</div>'
   +'<div class="t-right"><div class="t-rate">↑ '+fmtRate(d.net_tx_rate)+'　↓ '+fmtRate(d.net_rx_rate)+'</div><div class="small">累计 ↑ '+fmtBytes(d.net_tx)+'　↓ '+fmtBytes(d.net_rx)+'</div></div></div>';
  h+='<div class="ping">'+pingRow('电信',d.ping.ct)+pingRow('联通',d.ping.cu)+pingRow('移动',d.ping.cm)+'</div>';
  h+='<table><tr><th>三网线路</th><th>去程</th><th>回程</th></tr>'
   +'<tr><td>电信</td><td>'+cityTags(d.route.ct)+'</td><td>'+retTag(n.ret?n.ret.ct:null)+'</td></tr>'
   +'<tr><td>联通</td><td>'+cityTags(d.route.cu)+'</td><td>'+retTag(n.ret?n.ret.cu:null)+'</td></tr>'
   +'<tr><td>移动</td><td>'+cityTags(d.route.cm)+'</td><td>'+retTag(n.ret?n.ret.cm:null)+'</td></tr></table>'
   +'<div class="note">回程线路由国内探测节点上报, 未上报时显示 —。数据 '+timeAgo(n.lastSeen)+'更新。</div>';
  h+='<div class="metaform"><input id="n-'+esc(n.id)+'" type="text" maxlength="32" placeholder="备注名, 如 洛杉矶" value="'+esc(m.name||'')+'" style="width:160px"><input id="q-'+esc(n.id)+'" type="number" min="0" step="1" placeholder="流量配额 GB" value="'+(m.quotaGB||'')+'"><input id="e-'+esc(n.id)+'" type="date" value="'+(m.expiresAt||'')+'"><input id="p-'+esc(n.id)+'" type="text" placeholder="月费, 如 $3/月" value="'+esc(m.price||'')+'"><button data-node="'+esc(n.id)+'">保存设置</button><span class="saved" id="s-'+esc(n.id)+'"></span></div>';
  h+='</div>';
 });
 list.innerHTML=h;
 list.querySelectorAll('.metaform button').forEach(function(btn){
  btn.addEventListener('click',function(){
   var id=btn.getAttribute('data-node');
   var q=document.getElementById('q-'+id).value,e=document.getElementById('e-'+id).value,p=document.getElementById('p-'+id).value,nm=document.getElementById('n-'+id).value;
   fetch('/api/meta',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({node:id,name:nm==='' ?null:nm,quotaGB:q===''?null:Number(q),expiresAt:e==='' ?null:e,price:p==='' ?null:p})}).then(function(r){return r.json()}).then(function(j){document.getElementById('s-'+id).textContent=j.ok?'已保存':'保存失败: '+(j.error||'');if(j.ok)load()});
  });
 });
}
function load(){fetch('/api/status').then(function(r){if(r.status===401){location.reload();return null}return r.json()}).then(function(j){if(!j)return;updated.textContent='最近更新 '+new Date(j.now*1000).toLocaleTimeString('zh-CN');render(j.nodes,j.now)}).catch(function(){})}
document.getElementById('logout').addEventListener('click',function(){fetch('/api/logout',{method:'POST'}).then(function(){location.reload()})});
load();setInterval(load,5000);
</script></body></html>`;
