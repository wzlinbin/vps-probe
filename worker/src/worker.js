// vps-probe Worker: 面板 + 上报 API + 去程探测 agent(BoceWorkflow, 见 src/boce-workflow.js)
// 安全要点:
// - 面板需密码登录(Session Cookie, HttpOnly/Secure/SameSite, KV 存储, 7 天过期, 登录限流)
// - 上报需 Bearer token(与 secret 做 SHA-256 后定长比较), 严格 schema 校验, 限流 10 秒/节点
// - 所有响应带安全头, API 与页面均为 no-store; 不记录、不返回任何 secret
// - KV 只存节点快照/首次上线时间/节点元信息, 不存 token

export { BoceWorkflow } from './boce-workflow.js';

const SESSION_TTL = 7 * 86400; // 秒
const PUSH_MIN_INTERVAL = 10; // 秒/节点
const ONLINE_THRESHOLD = 120; // 秒内有上报算在线
const MAX_BODY = 65536;
const NODE_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;
const ROUTES = new Set(["163", "CN2", "CTGNet", "9929", "CMIN2", "4837", "CUG", "CMI", "9808", "CERNET", "CBN", "阿里云", "腾讯云", "华为云", "未知"]);

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
    // 新版 agent: 单城市 hz(杭州); 旧版: sh/gz/bj, 过渡期两者都接受
    const cities = v.hz !== undefined ? ["hz"] : ["sh", "gz", "bj"];
    for (const city of cities) {
      const cv = v[city];
      if (cv === undefined) return "route." + k + " 缺少 " + city;
      if (cv !== null && (typeof cv !== "string" || !ROUTES.has(cv))) return "route." + k + "." + city + " 非法";
    }
    for (const key of Object.keys(v)) if (!cities.includes(key)) return "route." + k + " 含未知字段";
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
    if (d.carrier === undefined) return "去程上报需 carrier";
    if (d.return_routes === null || typeof d.return_routes !== "object" || Array.isArray(d.return_routes)) return "return_routes 格式错误";
    for (const [k, v] of Object.entries(d.return_routes)) {
      if (!NODE_RE.test(k)) return "return_routes 目标非法";
      if (!["163", "CN2", "CTGNet", "9929", "CMIN2", "4837", "CUG", "CMI", "9808", "CERNET", "CBN", "阿里云", "腾讯云", "华为云"].includes(v)) return "return_routes 线路非法";
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
    if (path === "/api/node/delete" && request.method === "POST") {
      if (!(await getSession(request, env))) return json({ error: "未登录" }, 401);
      return handleNodeDelete(request, env);
    }
    if (path === "/api/agent-token" && request.method === "GET") {
      if (!(await getSession(request, env))) return json({ error: "未登录" }, 401);
      if (!env.AGENT_TOKEN) return json({ error: "未配置 AGENT_TOKEN" }, 500);
      return json({ ok: true, token: env.AGENT_TOKEN });
    }
    if (path === "/api/node/refresh-routes" && request.method === "POST") {
      if (!(await getSession(request, env))) return json({ error: "未登录" }, 401);
      return handleRefreshRoutes(request, env);
    }
    if (path === "/api/boce/start" && request.method === "POST") {
      if (!(await getSession(request, env))) return json({ error: "未登录" }, 401);
      return handleBoceStart(env);
    }
    if (path === "/api/boce/status" && request.method === "GET") {
      if (!(await getSession(request, env))) return json({ error: "未登录" }, 401);
      return handleBoceStatus(env);
    }
    if (path === "/" && request.method === "GET") {
      if (await getSession(request, env)) return html(DASHBOARD_HTML);
      return html(LOGIN_HTML);
    }
    return json({ error: "not found" }, 404);
  },
};

async function handleBoceStart(env) {
  // 单例 agent: 固定 id "boce-agent"; 已在跑时 create 会抛错, 返回已在跑.
  try {
    const instance = await env.BOCE_WORKFLOW.create({ id: "boce-agent", params: {} });
    return json({ ok: true, started: true, id: instance.id });
  } catch (e) {
    const msg = String(e && e.message || e);
    if (/already exists|duplicate/i.test(msg)) return json({ ok: true, started: false, note: "已在运行" });
    return json({ ok: false, error: msg.slice(0, 200) }, 500);
  }
}

async function handleBoceStatus(env) {
  try {
    const instance = await env.BOCE_WORKFLOW.get("boce-agent");
    return json({ ok: true, status: instance.status });
  } catch (e) {
    return json({ ok: true, status: "not-started", note: String(e && e.message || e).slice(0, 120) });
  }
}

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
  // 记下节点公网 IP(供面板生成 itdog 去程链接); 下次上报前该值为旧 IP, 不影响使用
  await env.PROBE_KV.put("node:" + data.node + ":latest", JSON.stringify({ receivedAt: now, data, ip: clientIP(request) }), { expirationTtl: 7 * 86400 });
  const first = await env.PROBE_KV.get("node:" + data.node + ":first_seen");
  if (first === null) await env.PROBE_KV.put("node:" + data.node + ":first_seen", String(now));
  // 去程探测结果: 国内探测节点向目标 VPS 探测, 按目标节点 + 探测方运营商存, 1 小时过期, 状态接口只取 10 分钟内的
  if (data.carrier && data.return_routes) {
    for (const [target, label] of Object.entries(data.return_routes)) {
      await env.PROBE_KV.put("return:" + target + ":" + data.carrier, JSON.stringify({ route: label, ts: now }), { expirationTtl: 3600 });
    }
  }
  const refreshKey = "refresh:" + data.node;
  const refresh = await env.PROBE_KV.get(refreshKey);
  if (refresh !== null) {
    await env.PROBE_KV.delete(refreshKey);
    return json({ ok: true, refreshRoutes: true });
  }
  return json({ ok: true });
}

// 立即检测: 面板点按钮后在 KV 留一个 10 分钟有效的标记;
// agent 下次上报(30 秒内)会在 push 响应里看到 refreshRoutes, 下轮立即重测线路。
async function handleRefreshRoutes(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "JSON 解析失败" }, 400);
  }
  if (typeof body.node !== "string" || !NODE_RE.test(body.node)) return json({ error: "node 非法" }, 400);
  await env.PROBE_KV.put("refresh:" + body.node, String(Math.floor(Date.now() / 1000)), { expirationTtl: 600 });
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
    // 去程: 取 boce.aliyun.com 探针上报的各运营商线路, 接受 8 天内的值
    // (测出正常线路后 7 天才重测, 没测出则 5 分钟后重试; 值必须在 KV 里留够 7 天)
    const retRaw = await Promise.all(["ct", "cu", "cm"].map((c) => env.PROBE_KV.get("return:" + id + ":" + c)));
    const ret = {};
    ["ct", "cu", "cm"].forEach((c, i) => {
      let v = null;
      if (retRaw[i]) { try { const p = JSON.parse(retRaw[i]); if (p && p.route && now - p.ts < 691200) v = p.route; } catch { /* 忽略损坏记录 */ } }
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
      ip: parsed.ip || null,
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

// 删除节点: 删上报记录、首次上报时间、备注设置及该节点作为去程目标的记录。
// agent 若仍在运行, 下次上报(30 秒内)会重新出现, 所以只对死节点真正有效。
async function handleNodeDelete(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "JSON 解析失败" }, 400);
  }
  if (typeof body.node !== "string" || !NODE_RE.test(body.node)) return json({ error: "node 非法" }, 400);
  const id = body.node;
  const keys = ["node:" + id + ":latest", "node:" + id + ":first_seen", "node:" + id + ":meta"];
  const retList = await env.PROBE_KV.list({ prefix: "return:" + id + ":" });
  for (const k of retList.keys) keys.push(k.name);
  let deleted = 0;
  for (const k of keys) {
    if ((await env.PROBE_KV.get(k)) !== null) {
      await env.PROBE_KV.delete(k);
      deleted++;
    }
  }
  return json({ ok: true, deleted });
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
.topbtns{display:flex;gap:8px}
.addnode{background:#1f2430;color:#fff;border:0;border-radius:8px;padding:6px 14px;font-size:13px;cursor:pointer}
.nav{position:sticky;top:0;z-index:20;background:#eef0f4;padding:10px 4px 12px;display:flex;gap:8px;flex-wrap:wrap;border-bottom:1px solid #dde1e8;margin-bottom:14px}
.nav button{display:flex;align-items:center;gap:6px;padding:6px 12px;border:1px solid #d8dce6;border-radius:999px;background:#fff;font-size:13px;color:#1f2430;cursor:pointer}
.nav button:hover{background:#f8f9fb}
.nav .dot{width:8px;height:8px;border-radius:50%;background:#9ca3af;flex:none}
.nav .dot.on{background:#16a34a}
.routes-actions{margin-top:10px;display:flex;gap:10px;align-items:center}
.routes-actions button{padding:6px 14px;border:1px solid #d8dce6;border-radius:8px;background:#fff;font-size:13px;color:#1f2430;cursor:pointer}
.routes-actions button:hover{background:#f8f9fb}
.routes-actions button:disabled{color:#9ca3af;cursor:default}
.refresh-status{color:#8a90a0;font-size:12px}
.modal{position:fixed;inset:0;background:rgba(15,20,35,.45);display:none;align-items:flex-start;justify-content:center;padding:40px 16px;z-index:50}
.modal.open{display:flex}
.modal .box{background:#fff;border-radius:16px;padding:22px;width:min(92vw,560px);box-shadow:0 12px 40px rgba(15,25,50,.25)}
.modal h3{margin:0 0 4px;font-size:17px}
.modal .hint{color:#8a90a0;font-size:12px;margin-bottom:14px;line-height:1.5}
.modal .row{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px}
.modal .row label{font-size:12px;color:#5b6474;width:100%}
.modal .row input,.modal .row select{padding:8px 10px;border:1px solid #d8dce6;border-radius:8px;font-size:13px;flex:1;min-width:140px}
.modal textarea{width:100%;min-height:64px;padding:10px;border:1px solid #d8dce6;border-radius:8px;font-size:12px;font-family:monospace;resize:vertical;background:#f8f9fb;box-sizing:border-box}
.modal .actions{display:flex;gap:8px;justify-content:flex-end;margin-top:12px}
.modal .actions button{padding:8px 16px;border-radius:8px;font-size:13px;cursor:pointer}
.modal .copy{background:#1f2430;color:#fff;border:0}
.modal .close{background:#fff;border:1px solid #d8dce6;color:#5b6474}
.card{background:#fff;border-radius:18px;box-shadow:0 8px 30px rgba(30,40,70,.08);padding:22px;margin-bottom:16px;scroll-margin-top:64px}
.card.flash{outline:2px solid #1f2430;outline-offset:3px}
.nodehead{display:flex;justify-content:space-between;align-items:baseline}
.nodehead h2{font-size:19px;margin:0}.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:1px}
.dot.on{background:#22c55e;box-shadow:0 0 0 3px rgba(34,197,94,.2)}.dot.off{background:#cbd5e1}
.nodehead .meta{color:#8a90a0;font-size:13px}
.nodehead .meta .warn{color:#dc2626}
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
.metaform button.del{background:#fff;color:#dc2626;border:1px solid #fca5a5}
.metaform button.del:hover{background:#fef2f2}
.metaform .saved{color:#16a34a;font-size:13px}
.empty{background:#fff;border-radius:18px;box-shadow:0 8px 30px rgba(30,40,70,.08);padding:40px 24px;text-align:center;color:#8a90a0}
@media(max-width:560px){.gauges{gap:8px}.prow{grid-template-columns:44px 62px 1fr 46px}}
</style></head><body><div class="wrap">
<div class="top"><div><h1>探针</h1><div class="sub" id="updated"></div></div><div class="topbtns"><button class="addnode" id="addnode">＋ 新增节点</button><button class="logout" id="logout">退出</button></div></div>
<div class="nav" id="nav"></div>
<div id="list"></div>
<div class="modal" id="addmodal"><div class="box">
<h3>新增节点</h3>
<div class="hint">填好后自动生成安装命令，在新 VPS 上用 root 跑一条命令即可。节点 id 留空则按主机名自动生成。</div>
<div class="row"><label>节点 id（可选）</label><input id="an-node" type="text" placeholder="如 la，留空自动生成"></div>
<div class="row"><label>显示名（可选）</label><input id="an-name" type="text" placeholder="如 洛杉矶"></div>
<div class="row"><label>安装命令</label><textarea id="an-cmd" readonly></textarea></div>
<div class="actions"><button class="close" id="an-close">关闭</button><button class="copy" id="an-copy">复制命令</button></div>
</div></div>
</div>
<script>
var list=document.getElementById('list'),updated=document.getElementById('updated'),nav=document.getElementById('nav');
function esc(s){return String(s).replace(/[&<>"']/g,function(c){return{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]})}
function fmtBytes(b){if(b>=1073741824)return (b/1073741824).toFixed(1)+' GB';if(b>=1048576)return (b/1048576).toFixed(1)+' MB';if(b>=1024)return (b/1024).toFixed(1)+' KB';return b+' B'}
function fmtRate(b){if(b>=1048576)return (b/1048576).toFixed(2)+' MB/s';if(b>=1024)return (b/1024).toFixed(1)+' KB/s';return b+' B/s'}
function pct(a,b){if(!b)return 0;return Math.min(100,Math.round(a/b*1000)/10)}
function fmtUptime(sec){if(!sec||sec<=0)return '未知';var d=Math.floor(sec/86400);if(d>=1)return d+' 天';var h=Math.floor(sec/3600);if(h>=1)return h+' 小时';return Math.floor(sec/60)+' 分钟'}
function timeAgo(ts){var s=Math.floor(Date.now()/1000-ts);if(s<60)return s+' 秒前';if(s<3600)return Math.floor(s/60)+' 分钟前';return Math.floor(s/3600)+' 小时前'}
function barColor(ms){if(ms==null)return '#cbd5e1';if(ms<120)return '#22c55e';if(ms<250)return '#eab308';return '#ef4444'}
function pingRow(name,r){var ms=r&&r.avg!=null?Math.round(r.avg):null;var loss=r&&r.loss!=null?r.loss:null;
 var w=ms==null?0:Math.min(100,ms/300*100);
 return '<div class="prow"><span>'+name+'</span><span>'+(ms==null?'—':ms+' ms')+'</span><span class="bar"><i style="width:'+w+'%;background:'+barColor(ms)+'"></i></span><span class="loss">'+(loss==null?'—':(Math.round(loss*10)/10)+'% 丢包')+'</span></div>'}
function routeTag(v){if(!v)return '<span class="route-tag unknown">未知</span>';if(v==='未知')return '<span class="route-tag unknown">未知</span>';return '<span class="route-tag">'+esc(v)+'</span>'}
function cityTags(r){
  if(typeof r === 'string') return routeTag(r);
  if(!r) return '<span class="route-tag unknown">未知</span>';
  var cities=[['sh','沪'],['gz','粤'],['bj','京'],['hz','杭州']];
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
// 设置表单正在输入时不重建卡片, 否则 5 秒自动刷新会清空刚输入的字符。
// editingMeta: 焦点在设置表单内(输入框或保存按钮)时正在编辑; snapshot/restore: 重建前后保留未保存的草稿。
function editingMeta(){var a=document.activeElement;return !!(a&&a.closest&&a.closest('.metaform'))}
function snapshotMeta(){var s={};document.querySelectorAll('.metaform input').forEach(function(i){s[i.id]=i.value});return s}
function restoreMeta(s){Object.keys(s).forEach(function(id){var el=document.getElementById(id);if(el)el.value=s[id]})}
function render(nodes,now){
 var draft=snapshotMeta();
 if(!nodes.length){nav.innerHTML='';list.innerHTML='<div class="empty">暂无节点<br><span style="font-size:13px">在 VPS 上安装 agent 并上报成功后,这里会显示数据。</span></div>';return}
 // 顶部导航条: 状态点 + 名称, 点即跳转定位到对应卡片(直接跳, 不用平滑滚动, 避免被 5 秒刷新打断)。
 var navHtml='';
 nodes.forEach(function(n){
  var d=n.data,m=n.meta||{};
  var displayName=(m.name&&m.name.length?m.name:(d.name&&d.name.length?d.name:n.id));
  navHtml+='<button data-node="'+esc(n.id)+'"><span class="dot '+(n.online?'on':'')+'"></span>'+esc(displayName)+'</button>';
 });
 nav.innerHTML=navHtml;
 nav.querySelectorAll('button').forEach(function(btn){
  btn.addEventListener('click',function(){
   var card=document.getElementById('card-'+btn.getAttribute('data-node'));
   if(!card)return;
   card.scrollIntoView({block:'start'});
   card.classList.add('flash');
   setTimeout(function(){card.classList.remove('flash')},1500);
  });
 });
 var h='';
 nodes.forEach(function(n){
  var d=n.data,m=n.meta||{};
  var memPct=pct(d.mem_used,d.mem_total),diskPct=pct(d.disk_used,d.disk_total);
  var traffic=d.net_rx+d.net_tx;
  var quotaPct=m.quotaGB?pct(traffic,m.quotaGB*1073741824):null;
  var remain='';
  if(m.expiresAt){var days=Math.ceil((new Date(m.expiresAt+'T00:00:00Z').getTime()-Date.now())/86400000);remain='剩余 '+days+' 天';}
  var warn='';
  if(remain)warn+=remain;
  if(m.price)warn+=(warn?' · ':'')+'续费金额：'+esc(m.price);
  var displayName=(m.name&&m.name.length?m.name:(d.name&&d.name.length?d.name:n.id));
  var idSuffix=(displayName!==n.id)?' · '+esc(n.id):'';
  h+='<div class="card" id="card-'+esc(n.id)+'"><div class="nodehead"><h2><span class="dot '+(n.online?'on':'off')+'"></span>'+esc(displayName)+'</h2><span class="meta">'+(n.online?'在线':'离线')+' · 运行 '+fmtUptime(d.uptime)+idSuffix+(warn?' · <span class="warn">'+warn+'</span>':'')+'</span></div>';
  h+='<div class="gauges">'
   +'<div class="tile"><div class="lab">CPU</div>'+gauge(d.cpu)+'<div class="small">'+d.load.map(function(x){return x.toFixed(2)}).join(', ')+'</div></div>'
   +'<div class="tile"><div class="lab">内存</div>'+gauge(memPct)+'<div class="small">'+fmtBytes(d.mem_used)+' / '+fmtBytes(d.mem_total)+'</div></div>'
   +'<div class="tile"><div class="lab">硬盘</div>'+gauge(diskPct)+'<div class="small">'+fmtBytes(d.disk_used)+' / '+fmtBytes(d.disk_total)+'</div></div>'
   +'</div>';
  h+='<div class="traffic"><div class="t-left"><div class="lab">流量</div><div class="t-big">'+fmtBytes(traffic)+'</div><div class="small">'+(m.quotaGB?('配额 '+m.quotaGB+' GB · 已用 '+quotaPct+'%'):'累计')+'</div>'+(quotaPct==null?'':'<div class="qbar"><i style="width:'+Math.min(quotaPct,100)+'%;background:'+gaugeColor(quotaPct)+'"></i></div>')+'</div>'
   +'<div class="t-right"><div class="t-rate">↑ '+fmtRate(d.net_tx_rate)+'　↓ '+fmtRate(d.net_rx_rate)+'</div><div class="small">累计 ↑ '+fmtBytes(d.net_tx)+'　↓ '+fmtBytes(d.net_rx)+'</div></div></div>';
  h+='<div class="ping">'+pingRow('电信',d.ping.ct)+pingRow('联通',d.ping.cu)+pingRow('移动',d.ping.cm)+'</div>';
  h+='<table><tr><th>三网线路</th><th>去程</th><th>回程</th></tr>'
   +'<tr><td>电信</td><td>'+retTag(n.ret?n.ret.ct:null)+'</td><td>'+cityTags(d.route.ct)+'</td></tr>'
   +'<tr><td>联通</td><td>'+retTag(n.ret?n.ret.cu:null)+'</td><td>'+cityTags(d.route.cu)+'</td></tr>'
   +'<tr><td>移动</td><td>'+retTag(n.ret?n.ret.cm:null)+'</td><td>'+cityTags(d.route.cm)+'</td></tr></table>'
   +'<div class="note">去程线路由 boce.aliyun.com 探针(杭州优先)探测, 测出线路后 7 天再测, 未测出 5 分钟后重试, 未探测时显示 —。回程线路为本节点向杭州目标探测的结果。数据 '+timeAgo(n.lastSeen)+'更新。</div>'
   +'<div class="routes-actions"><button class="refresh-routes" data-node="'+esc(n.id)+'">立即检测</button><span class="refresh-status" id="rs-'+esc(n.id)+'"></span></div>';
  h+='<div class="metaform"><input id="n-'+esc(n.id)+'" type="text" maxlength="32" placeholder="备注名, 如 洛杉矶" value="'+esc(m.name||'')+'" style="width:160px"><input id="q-'+esc(n.id)+'" type="number" min="0" step="1" placeholder="流量配额 GB" value="'+(m.quotaGB||'')+'"><input id="e-'+esc(n.id)+'" type="date" value="'+(m.expiresAt||'')+'"><input id="p-'+esc(n.id)+'" type="text" placeholder="月费, 如 $3/月" value="'+esc(m.price||'')+'"><button class="save" data-node="'+esc(n.id)+'">保存设置</button><button class="del" data-node="'+esc(n.id)+'">删除节点</button><span class="saved" id="s-'+esc(n.id)+'"></span></div>';
  h+='</div>';
 });
 list.innerHTML=h;
 restoreMeta(draft);
 list.querySelectorAll('.metaform button.save').forEach(function(btn){
  btn.addEventListener('click',function(){
   var id=btn.getAttribute('data-node');
   var q=document.getElementById('q-'+id).value,e=document.getElementById('e-'+id).value,p=document.getElementById('p-'+id).value,nm=document.getElementById('n-'+id).value;
   fetch('/api/meta',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({node:id,name:nm==='' ?null:nm,quotaGB:q===''?null:Number(q),expiresAt:e==='' ?null:e,price:p==='' ?null:p})}).then(function(r){return r.json()}).then(function(j){document.getElementById('s-'+id).textContent=j.ok?'已保存':'保存失败: '+(j.error||'');if(j.ok)load()});
  });
 });
 list.querySelectorAll('.metaform button.del').forEach(function(btn){
  btn.addEventListener('click',function(){
   var id=btn.getAttribute('data-node');
   var nm=document.getElementById('n-'+id).value||id;
   if(!confirm('确定删除节点 '+nm+' ('+id+') 吗?删除后将从面板移除,且不可恢复。若该节点 agent 仍在运行,30 秒后会重新出现。'))return;
   fetch('/api/node/delete',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({node:id})}).then(function(r){return r.json()}).then(function(j){
    if(j.ok){load(true)}
    else{alert('删除失败: '+(j.error||'未知错误'))}
   }).catch(function(){alert('删除失败: 网络错误')});
  });
 });
 list.querySelectorAll('.refresh-routes').forEach(function(btn){
  btn.addEventListener('click',function(){
   var id=btn.getAttribute('data-node');
   var st=document.getElementById('rs-'+id);
   btn.disabled=true;
   st.textContent='已发送检测请求, 约 1 分钟后更新';
   fetch('/api/node/refresh-routes',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({node:id})}).then(function(r){return r.json()}).then(function(j){
    if(!j.ok){st.textContent='发送失败: '+(j.error||'');btn.disabled=false}
   }).catch(function(){st.textContent='发送失败: 网络错误';btn.disabled=false});
  });
 });
}
function load(force){fetch('/api/status').then(function(r){if(r.status===401){location.reload();return null}return r.json()}).then(function(j){if(!j)return;if(!force&&editingMeta())return;updated.textContent='最近更新 '+new Date(j.now*1000).toLocaleTimeString('zh-CN');render(j.nodes,j.now)}).catch(function(){})}
document.getElementById('logout').addEventListener('click',function(){fetch('/api/logout',{method:'POST'}).then(function(){location.reload()})});
// 新增节点: 弹窗生成带 token 的安装命令, token 只在打开弹窗时取一次, 命令随表单实时生成。
var agentToken=null;
function shellQuote(s){if(/^[a-zA-Z0-9._:-]+$/.test(s))return s;return "'"+s.replace(/'/g,"'\\''")+"'"}
function buildInstallCmd(){
  var node=document.getElementById('an-node').value.trim();
  var name=document.getElementById('an-name').value.trim();
  var out=document.getElementById('an-cmd');
  if(!agentToken){out.value='正在获取 token...';return}
  var args=[location.origin,agentToken,node,name];
  var last=1;
  args.forEach(function(a,i){if(a)last=i});
  var parts=['curl -fsSL https://raw.githubusercontent.com/wzlinbin/vps-probe/main/agent/install.sh -o /tmp/install.sh && sudo bash /tmp/install.sh'];
  for(var i=0;i<=last;i++){parts.push(args[i]?shellQuote(args[i]):'""')}
  out.value=parts.join(' ');
}
function openAddModal(){
  document.getElementById('addmodal').classList.add('open');
  if(agentToken){buildInstallCmd();return}
  fetch('/api/agent-token').then(function(r){return r.json()}).then(function(j){
    if(j.ok&&j.token){agentToken=j.token;buildInstallCmd()}
    else{document.getElementById('an-cmd').value='获取 token 失败: '+(j.error||'未知错误')}
  }).catch(function(){document.getElementById('an-cmd').value='获取 token 失败: 网络错误'});
}
document.getElementById('addnode').addEventListener('click',openAddModal);
document.getElementById('an-close').addEventListener('click',function(){document.getElementById('addmodal').classList.remove('open')});
document.getElementById('addmodal').addEventListener('click',function(e){if(e.target===this)this.classList.remove('open')});
['an-node','an-name'].forEach(function(id){
  document.getElementById(id).addEventListener('input',buildInstallCmd);
});
document.getElementById('an-copy').addEventListener('click',function(){
  var cmd=document.getElementById('an-cmd').value;
  if(!cmd||!agentToken)return;
  var btn=this;
  function done(){btn.textContent='已复制';setTimeout(function(){btn.textContent='复制命令'},1500)}
  function fallbackCopy(){
    var ta=document.getElementById('an-cmd');
    ta.focus();ta.select();
    try{document.execCommand('copy');done()}catch(e){btn.textContent='复制失败，请手动选择'}
  }
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(cmd).then(done).catch(fallbackCopy)}
  else{fallbackCopy()}
});
load();setInterval(load,5000);
</script></body></html>`;
