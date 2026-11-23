// vps-probe 去程探测 agent (boce.aliyun.com), 跑在 Cloudflare Workflows 上.
// 常驻 agent 模式: 测一轮 -> 按结果睡觉(有结果 7 天、没结果 5 分钟) -> 睡醒自己再测、自己写 KV.
// 替代原来 VM 上 systemd 跑的 probe.py --daemon.
//
// 判线表与 agent/main.go、boce-probe/probe.py 一致(2026-11-23 联网核对 APNIC/IPinfo/HE.net 后订正).
// 关键: 223.120.0-127=CMI, 223.120.128-255=CMIN2; 223.96/223.99/211.136/183.240/120.196/117.128 是 9808 不是 CMIN2.
import { WorkflowEntrypoint } from 'cloudflare:workers';

const BOCE_BASE = 'https://boce.aliyun.com';
const RETURN_TTL = 8 * 86400; // 691200 秒 = 8 天
const SUCCESS_INTERVAL = 7 * 86400; // 7 天
const POLL_TIMEOUT = 300; // 轮询上限(秒)
const POLL_INTERVAL = 5; // 轮询间隔(秒)
const QUIET_SECONDS = 60; // 连续无新结果达到此时长即收尾
const VPS_GAP_SECONDS = 30; // 各 VPS 间隔
const CARRIERS = ['ct', 'cu', 'cm'];
const CARRIER_ZH = { ct: '电信', cu: '联通', cm: '移动' };
const ISP_ZH = { '电信': 'ct', '联通': 'cu', '移动': 'cm' };
const VALID_LINES = new Set(['163', 'CN2', 'CTGNet', '9929', '4837', 'CUG', 'CMIN2', 'CMI', '9808',
  'CERNET', 'CBN', '阿里云', '腾讯云', '华为云']);

// 判线网段表(与 agent/main.go routePrefixes 一致; 223.120 由 classifyIP 按第三段区分)
const ROUTE_PREFIXES = [
  ['202.97.', '163'], ['59.43.', 'CN2'],
  ['218.30.62.', 'CTGNet'], ['203.22.180.', 'CTGNet'],
  ['202.55.8.', 'CTGNet'], ['203.196.8.', 'CTGNet'], ['210.48.136.', 'CTGNet'], ['210.48.140.', 'CTGNet'],
  ['203.12.200.', 'CTGNet'], ['203.19.32.', 'CTGNet'], ['203.14.188.', 'CTGNet'],
  ['220.174.26.', 'CTGNet'], ['220.174.94.', 'CTGNet'],
  ['219.158.', '4837'],
  ['218.105.', '9929'], ['210.51.', '9929'], ['210.53.', '9929'], ['210.83.', '9929'],
  ['210.13.64.', '9929'], ['210.13.192.', '9929'], ['210.14.192.', '9929'], ['210.15.', '9929'],
  ['210.22.', '9929'],
  ['203.160.64.', 'CUG'], ['162.219.32.', 'CUG'], ['119.252.136.', 'CUG'],
  ['103.69.184.', 'CUG'], ['103.107.88.', 'CUG'], ['103.214.64.', 'CUG'],
  ['43.252.84.', 'CUG'], ['118.26.144.', 'CUG'],
  ['223.118.32.', 'CMIN2'],
  ['223.119.8.', 'CMIN2'], ['223.119.12.', 'CMIN2'],
  ['223.119.26.', 'CMIN2'], ['223.119.28.', 'CMIN2'],
  ['223.119.32.', 'CMIN2'], ['223.119.34.', 'CMIN2'], ['223.119.35.', 'CMIN2'],
  ['223.119.36.', 'CMIN2'], ['223.119.37.', 'CMIN2'],
  ['223.119.74.', 'CMIN2'], ['223.119.88.', 'CMIN2'],
  ['223.119.100.', 'CMIN2'], ['223.119.252.', 'CMIN2'],
  ['221.176.', '9808'], ['221.177.', '9808'], ['221.178.', '9808'], ['221.179.', '9808'],
  ['221.180.', '9808'], ['221.181.', '9808'], ['221.182.', '9808'], ['221.183.', '9808'],
  ['223.64.', '9808'], ['223.96.', '9808'], ['223.99.', '9808'],
  ['183.192.', '9808'], ['183.240.', '9808'],
  ['120.192.', '9808'], ['120.196.', '9808'], ['120.204.', '9808'],
  ['117.128.', '9808'],
  ['211.136.', '9808'], ['211.138.', '9808'], ['211.139.', '9808'],
  ['36.128.', '9808'], ['39.128.', '9808'],
  ['223.118.', 'CMI'], ['223.119.', 'CMI'],
  ['223.121.4.', 'CMI'], ['103.11.109.', 'CMI'],
];

function classifyIP(ip) {
  if (!ip || ip === '-' || ip === '*') return '';
  // 223.120.0.0/17=CMI, 223.120.128.0/17=CMIN2, 按第三段区分
  if (ip.startsWith('223.120.')) {
    const third = ip.slice('223.120.'.length).split('.', 1)[0];
    const n = parseInt(third, 10);
    if (Number.isNaN(n)) return '';
    return n >= 128 ? 'CMIN2' : 'CMI';
  }
  for (const [prefix, label] of ROUTE_PREFIXES) {
    if (ip.startsWith(prefix)) return label;
  }
  return '';
}

function classifyRoute(route) {
  // route: 元素为 {"rtt": n, "ip": "x.x.x.x"} 的数组(或 JSON 字符串)
  let hops = route;
  if (typeof hops === 'string') {
    try { hops = JSON.parse(hops); } catch { return '未知'; }
  }
  if (!Array.isArray(hops)) return '未知';
  for (const hop of hops) {
    if (!hop || typeof hop !== 'object') continue;
    const label = classifyIP(hop.ip || '');
    if (label) return label;
  }
  return '未知';
}

function routeIsEmpty(route) {
  let hops = route;
  if (typeof hops === 'string') {
    try { hops = JSON.parse(hops); } catch { return true; }
  }
  if (!Array.isArray(hops) || hops.length === 0) return true;
  return hops.every(h => !h || typeof h !== 'object' || !h.ip || h.ip === '-' || h.ip === '*');
}

function pickProbeNodes(allNodes) {
  // 按 杭州 > 浙江 > 江苏/上海 的优先级, 每运营商最多 2 个(首选+第一个备选)
  const tier = (node) => {
    const city = node['CityName.zh_CN'] || '';
    const region = node['Region.zh_CN'] || '';
    if (city === '杭州市') return 0;
    if (region === '浙江省') return 1;
    if (region === '江苏省' || region === '上海市') return 2;
    return 3;
  };
  const picked = {};
  for (const [carrierZh, carrier] of Object.entries(ISP_ZH)) {
    const cands = allNodes.filter(n => n['IspName.zh_CN'] === carrierZh);
    cands.sort((a, b) => {
      const t = tier(a) - tier(b);
      if (t !== 0) return t;
      const c = String(a['CityName.zh_CN'] || '').localeCompare(String(b['CityName.zh_CN'] || ''));
      if (c !== 0) return c;
      return String(a['City'] ?? '').localeCompare(String(b['City'] ?? ''));
    });
    const chosen = [];
    const seenTiers = new Set();
    for (const n of cands) {
      const t = tier(n);
      if (t > 2) break;
      if (!seenTiers.has(t)) { chosen.push(n); seenTiers.add(t); }
      if (chosen.length >= 3) break; // 每档 1 个, 最多 3 档(杭州/浙江/江苏上海); 浙江移动探针全空时可落到上海
    }
    picked[carrier] = chosen;
  }
  return picked;
}

// ---------- boce API (纯 fetch, 移植自 boce_tool.py) ----------

async function acquireXsrf() {
  const r = await fetch(BOCE_BASE + '/detect/dns', {
    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
  });
  if (!r.ok) throw new Error('boce detect 页 HTTP ' + r.status);
  const setCookie = r.headers.get('set-cookie') || '';
  const m = /XSRF-TOKEN=([^;]+)/.exec(setCookie);
  if (!m) throw new Error('未拿到 XSRF-TOKEN');
  return decodeURIComponent(m[1]);
}

async function callApi(xsrf, action, params, product = 'metrics20190101', includeUmid = false) {
  const form = new URLSearchParams({
    csrf_token: 'mock-sec-token', _csrf: 'mock-sec-token', sec_token: 'mock-sec-token',
    product, action, region: 'cn-hangzhou', params: JSON.stringify(params),
  });
  if (includeUmid) { form.set('umid', 'mock-umid'); form.set('collina', 'mock-collina-ua'); }
  const r = await fetch(BOCE_BASE + '/data/api.json?action=' + encodeURIComponent(action), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Xsrf-Token': xsrf, 'Cookie': 'XSRF-TOKEN=' + xsrf,
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Origin': BOCE_BASE, 'Referer': BOCE_BASE + '/detect/dns',
    },
    body: form.toString(),
  });
  if (!r.ok) throw new Error('boce API HTTP ' + r.status + ' [' + action + ']');
  const j = await r.json();
  if (j.code !== '200') throw new Error('boce API 错误 [' + action + ']: ' + (j.msg || j.message || '未知'));
  return j;
}

async function getProbeNodes(xsrf) {
  const j = await callApi(xsrf, 'DescribeSiteMonitorISPCityList', { City: '', TaskType: '9', IPV4: true });
  return j?.data?.IspCityList?.IspCity || [];
}

function genTaskName() {
  const hex = Math.random().toString(16).slice(2, 10);
  return hex + '_' + Date.now();
}

async function createTask(xsrf, targetIp, nodes) {
  const ispCity = nodes.map(n => ({ isp: n['Isp'], city: n['City'] }));
  const params = {
    'TaskList.1.TaskType': '9',
    'TaskList.1.TaskName': genTaskName(),
    'TaskList.1.Address': targetIp,
    'TaskList.1.Interval': 0,
    'TaskList.1.IspCity': ispCity,
    'TaskList.1.AgentGroup': '1',
    'TaskList.1.Options': { time_out: 30000, enable_operator_dns: true, count: 5 },
  };
  const j = await callApi(xsrf, 'BatchCreateOnceSiteMonitor', params, 'metrics20180308', true);
  const data = j?.data?.Data || [];
  const taskId = Array.isArray(data) ? (data[0]?.TaskId || data[0]?.taskId || null) : (data?.TaskId || null);
  // 兼容: 有的返回里 Data 是 {TaskId: ...} 或直接是 taskId 字符串
  if (taskId) return String(taskId);
  if (typeof data === 'string' && data) return data;
  throw new Error('建 boce 任务未返回 taskId');
}

async function pollOnce(xsrf, taskId) {
  const endTime = Date.now();
  const j = await callApi(xsrf, 'DescribeSiteMonitorLog', {
    TaskIds: taskId, UseFormatter: true, EndTime: endTime, StartTime: endTime - 7200000,
  }, 'metrics20190101', true);
  const dataStr = j?.data?.Data ?? '[]';
  let data = [];
  try { data = typeof dataStr === 'string' ? JSON.parse(dataStr) : (dataStr || []); } catch { data = []; }
  return Array.isArray(data) ? data : [];
}

// ---------- KV ----------

async function listVpsNodes(env) {
  const out = [];
  let cursor;
  do {
    const page = await env.PROBE_KV.list({ prefix: 'node:', cursor });
    for (const k of page.keys) {
      if (!k.name.endsWith(':latest')) continue;
      const nodeId = k.name.slice('node:'.length, -':latest'.length);
      const raw = await env.PROBE_KV.get(k.name);
      if (!raw) continue;
      let parsed;
      try { parsed = JSON.parse(raw); } catch { continue; }
      const ip = parsed?.ip;
      if (ip && ip !== 'unknown') out.push([nodeId, ip]);
    }
    cursor = page.cursor;
    if (page.list_complete) break;
  } while (cursor);
  out.sort((a, b) => (a[0] < b[0] ? -1 : 1));
  return out;
}

async function isDue(env, nodeId, carrier, now) {
  const raw = await env.PROBE_KV.get(`return:${nodeId}:${carrier}`);
  if (!raw) return [true, '无记录'];
  let val;
  try { val = JSON.parse(raw); } catch { return [true, '记录损坏']; }
  const route = val?.route || '';
  const ts = val?.ts || 0;
  const line = route.split(' ').pop() || '';
  if (VALID_LINES.has(line) && typeof ts === 'number' && ts > 0) {
    const age = now - ts;
    if (age >= SUCCESS_INTERVAL) return [true, `上次 ${route} 已是 ${Math.floor(age / 86400)} 天前`];
    return [false, `上次 ${route}(${Math.floor(age / 3600)} 小时前), 7 天内不重测`];
  }
  return [true, `上次 ${route || '无记录'}(非正常结果), 5 分钟后重试`];
}

async function nextWakeSeconds(env, vpsList, now) {
  let soonest = null;
  for (const [nodeId] of vpsList) {
    for (const carrier of CARRIERS) {
      const raw = await env.PROBE_KV.get(`return:${nodeId}:${carrier}`);
      let dueIn;
      if (!raw) {
        dueIn = 300;
      } else {
        try {
          const val = JSON.parse(raw);
          const route = val?.route || '';
          const ts = Number(val?.ts || 0);
          const line = route.split(' ').pop() || '';
          dueIn = (VALID_LINES.has(line) && ts > 0) ? (ts + SUCCESS_INTERVAL - now) : 300;
        } catch { dueIn = 300; }
      }
      if (soonest === null || dueIn < soonest) soonest = dueIn;
    }
  }
  if (soonest === null) return 3600;
  if (soonest <= 0) return 300;
  return Math.max(60, Math.min(soonest, 3600));
}

// ---------- Workflow ----------

export class BoceWorkflow extends WorkflowEntrypoint {
  async run(event, step) {
    const env = this.env;
    let round = 0;
    for (;;) {
      round += 1;
      const now = Math.floor(Date.now() / 1000);

      // 1) 读 VPS 节点
      const vpsList = await step.do(`r${round}-list-vps`, () => listVpsNodes(env));

      // 2) 拿 boce 探针节点(XSRF + 节点清单)
      const xsrf = await step.do(`r${round}-xsrf`, () => acquireXsrf());
      const allNodes = await step.do(`r${round}-nodes`, () => getProbeNodes(xsrf));
      const picked = pickProbeNodes(allNodes);

      // 3) 筛出本轮到期的(VPS, 运营商)
      const plan = {};
      for (const [nodeId, ip] of vpsList) {
        const due = [];
        for (const carrier of CARRIERS) {
          const [ok] = await step.do(`r${round}-due-${nodeId}-${carrier}`, () => isDue(env, nodeId, carrier, now));
          if (ok && picked[carrier] && picked[carrier].length > 0) due.push(carrier);
        }
        if (due.length > 0) plan[nodeId] = [ip, due];
      }
      if (Object.keys(plan).length === 0) {
        const wait = await step.do(`r${round}-wait-calc`, () => nextWakeSeconds(env, vpsList, Math.floor(Date.now() / 1000)));
        await step.sleep(`r${round}-sleep`, wait + ' seconds');
        continue;
      }

      // 4) 逐个 VPS 探测(间隔 30 秒控频)
      let vpsIdx = 0;
      for (const [nodeId, [ip, dueCarriers]] of Object.entries(plan)) {
        if (vpsIdx > 0) await step.sleep(`r${round}-gap-${nodeId}`, VPS_GAP_SECONDS + ' seconds');
        vpsIdx += 1;
        const sub = {};
        for (const c of dueCarriers) sub[c] = picked[c];
        const res = await this.probeVps(step, round, nodeId, ip, xsrf, sub);
        // 写 KV(只写测出结果的运营商; 全空/无结果的不写, 下轮 5 分钟后再试)
        for (const carrier of dueCarriers) {
          const r = res[carrier];
          if (!r) continue;
          const label = r.city ? `${r.city} ${r.line}` : r.line;
          const val = JSON.stringify({ route: label, ts: Math.floor(Date.now() / 1000) });
          await step.do(`r${round}-kv-${nodeId}-${carrier}`, () =>
            env.PROBE_KV.put(`return:${nodeId}:${carrier}`, val, { expirationTtl: RETURN_TTL }));
        }
      }

      // 5) 按结果睡觉, 醒来再测
      const wait = await step.do(`r${round}-wait-calc2`, () => nextWakeSeconds(env, vpsList, Math.floor(Date.now() / 1000)));
      await step.sleep(`r${round}-sleep2`, wait + ' seconds');
    }
  }

  // 对一个 VPS 做一次去程探测: 首选节点测一轮, 全空的运营商用备选再测一轮.
  // 返回 {carrier: {city, line}}.
  async probeVps(step, round, nodeId, targetIp, xsrf, candidatesByCarrier) {
    const out = {};
    const runOnce = async (tag, nodes) => {
      if (!nodes || nodes.length === 0) return {};
      const taskId = await step.do(`r${round}-${tag}-create-${nodeId}`, () => createTask(xsrf, targetIp, nodes));
      // 耐心轮询: 齐了 / 60 秒无新结果 / 300 秒上限才收尾
      const deadline = Date.now() + POLL_TIMEOUT * 1000;
      let best = [];
      let lastCount = 0;
      let lastNewAt = Date.now();
      let attempt = 0;
      while (Date.now() < deadline) {
        const data = await step.do(`r${round}-${tag}-poll-${nodeId}-${attempt}`, () => pollOnce(xsrf, taskId));
        attempt += 1;
        if (data.length > 0) {
          best = data;
          if (data.length >= nodes.length) break;
          if (data.length !== lastCount) { lastNewAt = Date.now(); lastCount = data.length; }
          else if (Date.now() - lastNewAt >= QUIET_SECONDS * 1000) break;
        }
        if (Date.now() >= deadline) break;
        await step.sleep(`r${round}-${tag}-wait-${nodeId}-${attempt}`, POLL_INTERVAL + ' seconds');
      }
      const res = {};
      for (const r of best) {
        const carrier = ISP_ZH[r.ispCN || ''];
        if (!carrier) continue;
        if ((r.errorCode || 0) !== 0) continue;
        const route = r.route || '';
        if (routeIsEmpty(route)) continue;
        res[carrier] = { city: r.cityCN || '', line: classifyRoute(route) };
      }
      return res;
    };
    // 按 杭州 -> 浙江 -> 江苏/上海 依次试, 空了就往下一档(浙江移动探针全空时落到上海)
    const tags = ['p', 'f1', 'f2'];
    for (let idx = 0; idx < 3; idx++) {
      const nodes = [];
      for (const [carrier, cands] of Object.entries(candidatesByCarrier)) {
        if (carrier in out) continue;
        if (cands && cands.length > idx) nodes.push(cands[idx]);
      }
      if (nodes.length === 0) break;
      Object.assign(out, await runOnce(tags[idx], nodes));
    }
    return out;
  }
}
