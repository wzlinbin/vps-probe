#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
vps-probe 去程探测: 用 boce.aliyun.com 从国内探针向各 VPS 做 traceroute, 判线后写 KV return: 供面板去程列显示.

探针节点选择(每运营商各 1 个, 优先级): 杭州 > 浙江省内 > 江苏/上海.
  - 杭州: 每家恰好 1 个节点(电信/联通/移动).
  - 浙江: 联通只有杭州 1 个, 掉线直接走上海/江苏; 电信有宁波/嘉兴/台州/温州, 移动有宁波/金华.
  - 江苏/上海: 上海三网各 1 个; 江苏徐州/无锡三网全有.

判线复用 agent 的 routePrefixes 网段表(见 agent/main.go, 2026-11-23 联网核对 APNIC/IPinfo/HE.net 后订正):
  163: 202.97.0-95; CN2: 59.43/16; CTGNet: 218.30.62.0/23、203.22.180.0/24 等窄段;
  联通 169: 219.158.0-127(AS4837); 联通 A 网/9929: 218.105/210.51/210.53/210.83/210.13.64/18/210.13.192/19/210.14.192/18/210.15/17/210.22(部分);
  联通国际 CUG: 203.160.64.0/19 + 162.219.32/21、119.252.136/21 等;
  CMIN2(AS58807 仅 33 个前缀): 223.118.32/24、223.119.8/12/22、223.119.26/28/74/88/23、223.119.32/34/35/36/37/100/24、223.119.252/23、223.120.128.0/17;
  9808/CMNET: 221.176.0.0/13、223.64/10、183.192/10、120.192/10、117.128/10、36.128/10、39.128/10;
  CMI: 223.118/119(除 CMIN2 更具体前缀外)、223.120.0.0/17。
  关键纠正: 223.120.16/17/19/22 是 CMI 不是 CMIN2; 223.96/223.99/211.136/183.240/120.196/117.128 是 9808 不是 CMIN2。
  223.120.0-127=CMI, 223.120.128-255=CMIN2, 由 classify_ip 按第三段区分。

探测节奏(用户定的规则):
  - 测出正常线路(163/CN2/CTGNet/9929/4837/CUG/CMIN2/CMI/9808/CERNET/CBN/阿里云/腾讯云/华为云): 7 天后再测.
  - 没测出结果(路由全空、探针没回数据, 或"未知"): 不写 KV, 5 分钟后再试.
  - 常驻 agent 模式(--daemon): agent 自己管时间, 测完按结果睡觉(有结果睡到 7 天后、
    没结果睡 5 分钟), 睡醒自己再测、自己上报, 不靠外部定时任务每几分钟去"看".
  - KV 写入 TTL 8 天(覆盖 7 天间隔), 面板接受 8 天内的值.

控频(避免触发 boce.aliyun.com 频次风控):
  - 每 VPS 每轮只发 1 个任务(到期运营商各 1 个节点), 不多测.
  - 各 VPS 间隔 30 秒, 顺序跑, 不并发.
  - 轮询耐心等(齐了/60 秒无新结果/300 秒上限才收尾), 不因 6 秒没新结果就截断.
  - XSRF 会话由 boce_tool 缓存(2 小时), 不重复拿.

KV 写入: return:<vps-id>:<carrier> = {"route": "<城市> <线路>", "ts": <unix秒>}, TTL 691200(8天).
  标签如 "杭州 163" / "上海 CN2" / "杭州 未知". 面板去程列直接显示该字符串.
  写 KV 走 wrangler-auth.py(Cloudflare token 由连接器提供).

用法:
  python3 probe.py                       # 按到期规则测一轮就退出
  python3 probe.py --daemon              # 常驻 agent: 测完睡觉, 到时间自己再测
  python3 probe.py --node la             # 只看 la 的到期运营商
  python3 probe.py --force               # 不看到期规则, 全部重测(手动用)
  python3 probe.py --dry-run             # 只打印到期情况, 不发探测、不写 KV
  python3 probe.py --list-nodes          # 打印每运营商选中的探针节点后退出
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

# boce 封装脚本位置(由 get-skill 安装)
BOCE_SKILL_DIR = Path.home() / ".codex" / "skills" / "alibabacloud-website-probe"
BOCE_SCRIPTS_DIR = BOCE_SKILL_DIR / "scripts"
sys.path.insert(0, str(BOCE_SCRIPTS_DIR))

from boce_tool import (PRODUCT_QUERY, _call_api, _create_task,  # noqa: E402
                        build_session, get_probe_nodes)

# ---------- 配置 ----------
KV_NAMESPACE_ID = "02c6577154654aec8bb7a0436d0e3ca3"
WRANGLER_AUTH = str(Path.home() / "workspace" / "custom-connectors" / "custom.cloudflare" / "bin" / "wrangler-auth.py")
WORKER_DIR = str(Path.home() / "workspace" / "vps-probe" / "worker")
RETURN_TTL = 8 * 86400  # 691200 秒 = 8 天, 覆盖 7 天探测间隔
SUCCESS_INTERVAL = 7 * 86400  # 604800 秒 = 7 天; 有正常结果后隔这么久再测
POLL_TIMEOUT = 300  # traceroute 轮询上限(秒)
POLL_INTERVAL = 5  # 轮询间隔(秒)
QUIET_SECONDS = 60  # 连续无新结果达到此时长即收尾(避免空等满超时)
VPS_GAP_SECONDS = 30  # 各 VPS 间隔, 避免集中请求
CARRIERS = ["ct", "cu", "cm"]
CARRIER_ZH = {"ct": "电信", "cu": "联通", "cm": "移动"}
ISP_ZH = {"电信": "ct", "联通": "cu", "移动": "cm"}
VALID_LINES = {"163", "CN2", "CTGNet", "9929", "4837", "CUG", "CMIN2", "CMI", "9808",
               "CERNET", "CBN", "阿里云", "腾讯云", "华为云"}  # 正常线路; "未知"不算正常结果, 5 分钟后重试

# 判线网段表(与 agent/main.go routePrefixes 一致, 按前缀匹配; 223.120 由 classify_ip 按第三段区分)
ROUTE_PREFIXES = [
    ("202.97.", "163"), ("59.43.", "CN2"),
    ("218.30.62.", "CTGNet"), ("203.22.180.", "CTGNet"),
    ("202.55.8.", "CTGNet"), ("203.196.8.", "CTGNet"), ("210.48.136.", "CTGNet"), ("210.48.140.", "CTGNet"),
    ("203.12.200.", "CTGNet"), ("203.19.32.", "CTGNet"), ("203.14.188.", "CTGNet"),
    ("220.174.26.", "CTGNet"), ("220.174.94.", "CTGNet"),
    ("219.158.", "4837"),
    ("218.105.", "9929"), ("210.51.", "9929"), ("210.53.", "9929"), ("210.83.", "9929"),
    ("210.13.64.", "9929"), ("210.13.192.", "9929"), ("210.14.192.", "9929"), ("210.15.", "9929"),
    ("210.22.", "9929"),
    ("203.160.64.", "CUG"), ("162.219.32.", "CUG"), ("119.252.136.", "CUG"),
    ("103.69.184.", "CUG"), ("103.107.88.", "CUG"), ("103.214.64.", "CUG"),
    ("43.252.84.", "CUG"), ("118.26.144.", "CUG"),
    ("223.118.32.", "CMIN2"),
    ("223.119.8.", "CMIN2"), ("223.119.12.", "CMIN2"),
    ("223.119.26.", "CMIN2"), ("223.119.28.", "CMIN2"),
    ("223.119.32.", "CMIN2"), ("223.119.34.", "CMIN2"), ("223.119.35.", "CMIN2"),
    ("223.119.36.", "CMIN2"), ("223.119.37.", "CMIN2"),
    ("223.119.74.", "CMIN2"), ("223.119.88.", "CMIN2"),
    ("223.119.100.", "CMIN2"), ("223.119.252.", "CMIN2"),
    ("221.176.", "9808"), ("221.177.", "9808"), ("221.178.", "9808"), ("221.179.", "9808"),
    ("221.180.", "9808"), ("221.181.", "9808"), ("221.182.", "9808"), ("221.183.", "9808"),
    ("223.64.", "9808"), ("223.96.", "9808"), ("223.99.", "9808"),
    ("183.192.", "9808"), ("183.240.", "9808"),
    ("120.192.", "9808"), ("120.196.", "9808"), ("120.204.", "9808"),
    ("117.128.", "9808"),
    ("211.136.", "9808"), ("211.138.", "9808"), ("211.139.", "9808"),
    ("36.128.", "9808"), ("39.128.", "9808"),
    ("223.118.", "CMI"), ("223.119.", "CMI"),
    ("223.121.4.", "CMI"), ("103.11.109.", "CMI"),
]


def classify_ip(ip):
    """按网段表给单个 IP 判线, 命中返回线路名, 否则返回 ''."""
    if not ip or ip in ("-", "*"):
        return ""
    # 223.120.0.0/17=CMI, 223.120.128.0/17=CMIN2, 按第三段区分
    if ip.startswith("223.120."):
        rest = ip[len("223.120."):]
        third = rest.split(".", 1)[0]
        try:
            n = int(third)
        except ValueError:
            return ""
        return "CMIN2" if n >= 128 else "CMI"
    for prefix, label in ROUTE_PREFIXES:
        if ip.startswith(prefix):
            return label
    return ""


def classify_route(route_json_str, ip_geo_map_str=None):
    """给一次 traceroute 结果判线.

    route 是 JSON 字符串, 元素为 {"rtt": n, "ip": "x.x.x.x"}.
    取路由上第一个命中网段表的跳点作为线路(流量进入该骨干即定线).
    若无跳点命中, 返回 '未知'.
    """
    try:
        hops = json.loads(route_json_str) if isinstance(route_json_str, str) else (route_json_str or [])
    except (json.JSONDecodeError, TypeError):
        return "未知"
    for hop in hops:
        if not isinstance(hop, dict):
            continue
        label = classify_ip(hop.get("ip", ""))
        if label:
            return label
    return "未知"


def pick_probe_nodes(all_nodes):
    """按 杭州 > 浙江 > 江苏/上海 的优先级, 每运营商选候选节点列表(按优先级排序).

    返回 {carrier: [node, ...]}, 每运营商最多 3 个: 首选(杭州) + 浙江备选 + 江苏/上海备选.
    某运营商三档都无节点时对应列表为空.
    """
    def tier(node):
        city = node.get("CityName.zh_CN", "")
        region = node.get("Region.zh_CN", "")
        if city == "杭州市":
            return 0
        if region == "浙江省":
            return 1
        if region in ("江苏省", "上海市"):
            return 2
        return 3

    picked = {}
    for carrier_zh, carrier in ISP_ZH.items():
        cands = [n for n in all_nodes if n.get("IspName.zh_CN") == carrier_zh]
        cands.sort(key=lambda n: (tier(n), n.get("CityName.zh_CN", ""), str(n.get("City", ""))))
        # 只保留 杭州/浙江/江苏/上海 三档, 每档最多取 1 个(首选+浙江备选+江苏/上海备选)
        chosen = []
        seen_tiers = set()
        for n in cands:
            t = tier(n)
            if t > 2:
                break
            if t not in seen_tiers:
                chosen.append(n)
                seen_tiers.add(t)
            if len(chosen) >= 3:
                break
        picked[carrier] = chosen
    return picked


def route_is_empty(route_json_str):
    """路由是否全空(所有跳点都是 '-' 或无跳点). 全空表示探针没返回可用数据, 不是测出未知线路."""
    try:
        hops = json.loads(route_json_str) if isinstance(route_json_str, str) else (route_json_str or [])
    except (json.JSONDecodeError, TypeError):
        return True
    if not hops:
        return True
    return all(not isinstance(h, dict) or not h.get("ip") or h.get("ip") in ("-", "*") for h in hops)


def wrangler(*args, input_text=None, timeout=120):
    """调 wrangler-auth.py 执行一条 wrangler 命令, 返回 (returncode, stdout, stderr)."""
    cmd = ["python3", WRANGLER_AUTH, *args]
    try:
        r = subprocess.run(cmd, input=input_text, capture_output=True, text=True,
                           cwd=WORKER_DIR, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "wrangler 超时"


def kv_get(key):
    rc, out, err = wrangler("kv", "key", "get", key, "--namespace-id", KV_NAMESPACE_ID, "--remote")
    if rc != 0:
        return None
    return out


def kv_put(key, value_json, ttl=RETURN_TTL):
    # wrangler kv key put 的 TTL 参数是 --ttl, 不是 --expiration-ttl
    rc, out, err = wrangler("kv", "key", "put", key, "--value", value_json,
                            "--namespace-id", KV_NAMESPACE_ID, "--remote",
                            "--ttl", str(ttl))
    return rc == 0


def list_vps_nodes():
    """从 KV 读出全部 VPS 节点 id 与公网 IP. 返回 [(node_id, ip), ...]."""
    rc, out, err = wrangler("kv", "key", "list", "--namespace-id", KV_NAMESPACE_ID, "--remote")
    if rc != 0:
        print(f"[ERROR] KV list 失败: {err.strip()[:200]}")
        return []
    try:
        keys = json.loads(out)
    except json.JSONDecodeError:
        print("[ERROR] KV list 返回非 JSON")
        return []
    nodes = []
    for k in keys:
        name = k.get("name", "")
        if not name.startswith("node:") or not name.endswith(":latest"):
            continue
        node_id = name[len("node:"):-len(":latest")]
        raw = kv_get(name)
        if not raw:
            continue
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            continue
        ip = parsed.get("ip")
        if ip and ip != "unknown":
            nodes.append((node_id, ip))
    nodes.sort()
    return nodes


def is_due(node_id, carrier, now=None):
    """判断某对(VPS, 运营商)本轮是否到期该测.

    规则(用户定):
      - KV 无值(从未测过, 或上次没测出结果所以没写): 到期, 该测.
      - KV 有值且线路是正常结果或"未知": 距上次探测满 7 天才到期.
    返回 (是否到期, 原因说明).
    """
    now = now if now is not None else int(time.time())
    raw = kv_get(f"return:{node_id}:{carrier}")
    if not raw:
        return True, "无记录"
    try:
        val = json.loads(raw)
    except json.JSONDecodeError:
        return True, "记录损坏"
    route = val.get("route", "")
    ts = val.get("ts", 0)
    line = route.split()[-1] if route.split() else ""
    if line in VALID_LINES and isinstance(ts, (int, float)) and ts > 0:
        age = now - int(ts)
        if age >= SUCCESS_INTERVAL:
            return True, f"上次 {route} 已是 {age // 86400} 天前"
        return False, f"上次 {route}({age // 3600} 小时前), 7 天内不重测"
    # "未知"或无有效线路: 不算正常结果, 5 分钟后重试(下一轮 cron 即到期)
    return True, f"上次 {route or '无记录'}(非正常结果), 5 分钟后重试"


def detect_traceroute_patient(session, target_ip, nodes, poll_timeout=POLL_TIMEOUT):
    """发一次 traceroute 任务并耐心等结果.

    不用库里的 detect_traceroute: 它 2 次轮询数量不变(6 秒)就提前返回,
    traceroute 节点回得有快有慢, 第一个回了、另两个还没回就被截断.
    这里只在节点齐了、或 60 秒无新结果、或 300 秒上限时才收尾.
    """
    options = {"time_out": 30000, "enable_operator_dns": True, "count": 5}
    try:
        task_id = _create_task(session, "9", target_ip, nodes, options, agent_group="1")
    except Exception as e:
        print(f"[WARN] 创建 traceroute 任务失败({target_ip}): {e}")
        return []
    expected = len(nodes)
    deadline = time.time() + poll_timeout
    best = []
    last_count = 0
    last_new_at = time.time()
    while time.time() < deadline:
        end_time = int(time.time() * 1000)
        params = {"TaskIds": task_id, "UseFormatter": True,
                  "EndTime": end_time, "StartTime": end_time - 7200000}
        try:
            result = _call_api(session, "DescribeSiteMonitorLog", params,
                               product=PRODUCT_QUERY, include_umid=True)
        except Exception as e:
            print(f"[WARN] 轮询失败: {e}")
            time.sleep(POLL_INTERVAL)
            continue
        data_str = result.get("data", {}).get("Data", "[]")
        try:
            data = json.loads(data_str) if isinstance(data_str, str) else (data_str or [])
        except json.JSONDecodeError:
            data = []
        if data:
            best = data
            cur = len(data)
            if cur >= expected:
                return best
            if cur != last_count:
                last_new_at = time.time()
                last_count = cur
            elif time.time() - last_new_at >= QUIET_SECONDS:
                return best
        time.sleep(POLL_INTERVAL)
    return best


def probe_one_vps(session, target_ip, candidates_by_carrier, poll_timeout=POLL_TIMEOUT):
    """对一个 VPS IP 做一次去程探测(只测传入的运营商).

    按 杭州 -> 浙江 -> 江苏/上海 依次试, 空了就往下一档(浙江移动探针全空时落到上海).
    返回 {carrier: {"city": 城市, "line": 线路}}.
    某运营商三档都无可用路由时该运营商缺失, 调用方不写 KV(保留旧值, 下轮 5 分钟后再试).
    有跳点但判不出线路时才写"未知"(算一次有结果, 7 天后再测).
    """
    def run(nodes):
        if not nodes:
            return {}
        results = detect_traceroute_patient(session, target_ip, nodes, poll_timeout=poll_timeout)
        out = {}
        for r in results:
            carrier = ISP_ZH.get(r.get("ispCN", ""))
            if not carrier:
                continue
            if r.get("errorCode", 0) != 0:
                print(f"[WARN] {target_ip} {r.get('ispCN')} 探针报错: {r.get('message','')}")
                continue
            route = r.get("route", "")
            if route_is_empty(route):
                print(f"[WARN] {target_ip} {r.get('ispCN')}({r.get('cityCN')}) 路由全空, 探针未返回数据")
                continue
            out[carrier] = {"city": r.get("cityCN", ""), "line": classify_route(route)}
        return out

    out = {}
    for idx in range(3):
        nodes = []
        for carrier, cands in candidates_by_carrier.items():
            if carrier in out:
                continue
            if cands and len(cands) > idx:
                nodes.append(cands[idx])
        if not nodes:
            break
        out.update(run(nodes))
    return out


def next_wake_seconds(vps_list, now=None):
    """算 agent 下次该醒来的等待秒数.

    对每对(VPS, 运营商):
      - 有正常线路: 下次到期 = 上次 ts + 7 天.
      - 无记录/"未知": 下次到期 = 现在 + 5 分钟(重试).
    取所有到期时间里最近的一个; 若全部都未到期, 睡到最近的到期时间(最多 1 小时, 到时再算一次).
    返回等待秒数(>= 60).
    """
    now = now if now is not None else int(time.time())
    soonest = None
    for node_id, _ip in vps_list:
        for carrier in CARRIERS:
            raw = kv_get(f"return:{node_id}:{carrier}")
            if not raw:
                due_in = 300  # 无记录, 5 分钟后重试
            else:
                try:
                    val = json.loads(raw)
                    route = val.get("route", "")
                    ts = int(val.get("ts", 0))
                    line = route.split()[-1] if route.split() else ""
                except (json.JSONDecodeError, ValueError, TypeError):
                    due_in = 300
                else:
                    if line in VALID_LINES and ts > 0:
                        due_in = (ts + SUCCESS_INTERVAL) - now
                    else:
                        due_in = 300  # "未知"等非正常结果, 5 分钟后重试
            if soonest is None or due_in < soonest:
                soonest = due_in
    if soonest is None:
        return 3600
    # 已到期则 5 分钟后(给刚测完的留间隔); 未到期则睡到最近到期时间, 最多 1 小时
    if soonest <= 0:
        return 300
    return max(60, min(soonest, 3600))


def run_one_round(session, picked, vps_list, force=False):
    """跑一轮探测: 只测到期的(VPS, 运营商), 写 KV. 返回测到的结果数."""
    now = int(time.time())
    plan = {}
    for node_id, ip in vps_list:
        due = []
        for carrier in CARRIERS:
            if force:
                due.append(carrier)
                continue
            ok, reason = is_due(node_id, carrier, now=now)
            if ok:
                due.append(carrier)
        if due:
            plan[node_id] = (ip, due)
    if not plan:
        print("[INFO] 本轮无到期的(VPS, 运营商), 不发探测", flush=True)
        return 0
    print(f"[INFO] 本轮待测: {[(n, [CARRIER_ZH[c] for c in d]) for n, (_, d) in plan.items()]}", flush=True)
    done = 0
    for idx, (node_id, (ip, due_carriers)) in enumerate(plan.items()):
        if idx > 0:
            print(f"[INFO] 间隔 {VPS_GAP_SECONDS}s 后测下一个 VPS(控频)...", flush=True)
            time.sleep(VPS_GAP_SECONDS)
        sub = {c: picked[c] for c in due_carriers if picked.get(c)}
        print(f"[INFO] 探测 {node_id} ({ip}) 到期运营商: {[CARRIER_ZH[c] for c in sub]}...", flush=True)
        res = probe_one_vps(session, ip, sub)
        if not res:
            print(f"[WARN] {node_id}: 未拿到任何运营商结果, 不写 KV, 5 分钟后再试", flush=True)
            continue
        for carrier in due_carriers:
            r = res.get(carrier)
            if not r:
                print(f"[WARN] {node_id} {CARRIER_ZH[carrier]}: 无结果, 不写 KV, 5 分钟后再试", flush=True)
                continue
            label = f"{r['city']} {r['line']}" if r['city'] else r['line']
            key = f"return:{node_id}:{carrier}"
            val = json.dumps({"route": label, "ts": int(time.time())}, ensure_ascii=False)
            ok = kv_put(key, val)
            print(f"[INFO] {node_id} {CARRIER_ZH[carrier]}: {label} -> {key} {'OK(7 天后再测)' if ok else '写 KV 失败'}", flush=True)
            if ok:
                done += 1
    return done


def main():
    ap = argparse.ArgumentParser(description="vps-probe 去程探测(boce.aliyun.com)")
    ap.add_argument("--node", help="只看指定节点 id 的到期运营商")
    ap.add_argument("--force", action="store_true", help="不看到期规则, 全部重测(手动用)")
    ap.add_argument("--dry-run", action="store_true", help="只打印到期情况, 不发探测、不写 KV")
    ap.add_argument("--list-nodes", action="store_true", help="打印每运营商选中的探针节点后退出")
    ap.add_argument("--daemon", action="store_true", help="常驻 agent 模式: 测完按结果睡 7 天或 5 分钟, 到时间自己再测")
    args = ap.parse_args()

    session = build_session()
    print("[INFO] 获取 traceroute 探针节点...", flush=True)
    all_nodes = get_probe_nodes(session, task_type="9")
    print(f"[INFO] 探针节点总数: {len(all_nodes)}", flush=True)
    picked = pick_probe_nodes(all_nodes)
    for c in CARRIERS:
        cands = picked.get(c, [])
        if cands:
            print(f"[INFO] {CARRIER_ZH[c]}: 首选 {cands[0].get('CityName.zh_CN')}({cands[0].get('Region.zh_CN')})"
                  + (f" 备选 {cands[1].get('CityName.zh_CN')}({cands[1].get('Region.zh_CN')})" if len(cands) > 1 else ""), flush=True)
        else:
            print(f"[WARN] {CARRIER_ZH[c]}: 杭州/浙江/江苏/上海均无探针节点, 该运营商本次跳过", flush=True)
    if args.list_nodes:
        return 0
    if not any(picked.values()):
        print("[ERROR] 三个运营商均无可用探针节点")
        return 1

    vps_list = list_vps_nodes()
    if args.node:
        vps_list = [x for x in vps_list if x[0] == args.node]
        if not vps_list:
            print(f"[ERROR] KV 中无节点 {args.node} 或无公网 IP")
            return 1
    print(f"[INFO] 待测 VPS: {[(n, ip) for n, ip in vps_list]}", flush=True)

    if args.dry_run:
        now = int(time.time())
        for node_id, _ip in vps_list:
            for carrier in CARRIERS:
                ok, reason = is_due(node_id, carrier, now=now)
                print(f"[INFO] {node_id} {CARRIER_ZH[carrier]}: {'到期' if ok else '跳过'}({reason})", flush=True)
        return 0

    if args.daemon:
        print("[INFO] 常驻 agent 模式启动: 测完按结果睡觉, 到时间自己再测", flush=True)
        while True:
            try:
                run_one_round(session, picked, vps_list, force=args.force)
            except Exception as e:
                print(f"[WARN] 本轮异常: {e}, 5 分钟后重试", flush=True)
            wait = next_wake_seconds(vps_list)
            print(f"[INFO] 睡 {wait // 60} 分 {wait % 60} 秒后醒来再测", flush=True)
            time.sleep(wait)
        return 0

    run_one_round(session, picked, vps_list, force=args.force)
    print("[INFO] 完成")
    return 0


if __name__ == "__main__":
    sys.exit(main())
