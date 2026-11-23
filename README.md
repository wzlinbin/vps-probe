# VPS 探针 (vps-probe)

自建的轻量 VPS 监控面板:Agent 采数据 → Cloudflare Worker 收数据、存 KV → 面板页面展示。
面板地址: https://vps-probe.wzlinbin.workers.dev

## 结构

```
vps-probe/
  agent/                 # VPS 上跑的 agent (Go, 零依赖, 静态二进制)
    main.go              # 采集 + 上报
    go.mod
    build.sh             # 交叉编译 amd64 + arm64 到 dist/
    install.sh           # 在 VPS 上一键安装 (systemd)
  worker/                # Cloudflare Worker (面板 + API)
    src/worker.js        # 全部后端逻辑 + 面板/登录页 (单文件, 无外部资源)
    wrangler.toml        # KV 绑定 PROBE_KV
  dist/                  # 编译好的二进制
  README.md
```

## Agent 采集内容

- CPU 使用率、loadavg、内存、硬盘、流量速率 + 跨重启累计流量(状态文件 `/var/lib/vps-probe/state.json`)
- 三网 ping: 电信 114.114.114.114、联通 123.125.81.6、移动 211.136.17.107(延迟 + 丢包率)
- 去程线路: traceroute 跳点 IP 按网段启发式分类 163 / 9929 / CMIN2 / 4837, 命中不了显示"未知"
- 回程线路: 需国内节点探测, 当前版本未测, 面板显示"—"

Agent 每 30 秒 POST 一次 JSON 到 `https://vps-probe.wzlinbin.workers.dev/api/push`。
本身不监听任何端口, 只出站 HTTPS。

## 在 VPS 上安装

不用手工传文件, 在 VPS 上一条命令(会从 GitHub 拉 install.sh, 再自动下对应架构的二进制):

```bash
curl -fsSL https://raw.githubusercontent.com/wzlinbin/vps-probe/main/agent/install.sh -o install.sh && sudo bash install.sh https://vps-probe.wzlinbin.workers.dev <上报token> <节点id>
# 例如: curl -fsSL https://raw.githubusercontent.com/wzlinbin/vps-probe/main/agent/install.sh -o install.sh && sudo bash install.sh https://vps-probe.wzlinbin.workers.dev <token> la
```

安装脚本会: 装二进制到 /usr/local/bin、写 600 权限的 /etc/vps-probe/env、
写 systemd unit、干跑一次验证采集、enable 并启动。
查看日志: `journalctl -u vps-probe-agent -f`

节点 id 只允许小写字母、数字、连字符, 1–32 位。多个 VPS 各装一个, 节点 id 不同即可,
面板会列出所有节点。

卸载: `systemctl disable --now vps-probe-agent; rm /usr/local/bin/vps-probe-agent /etc/systemd/system/vps-probe-agent.service; rm -rf /etc/vps-probe /var/lib/vps-probe`

## 面板功能

- 登录后查看各节点: CPU/内存/硬盘/流量、上下行速率、三网延迟条、去程线路
- 每个节点可设置流量配额 GB、到期日、月费(面板"保存设置"), 用于显示流量占比和剩余天数
- 在线判断: 120 秒内有上报算在线; "在线 X 天"按首次上报时间算
- 每 5 秒自动刷新

## 安全性

- 上报: Bearer token 鉴权(与 Worker secret 做 SHA-256 后定长比较)、
  严格 schema 校验(字段白名单、数值范围、时间戳与服务器相差 < 1 小时)、
  10 秒/节点限流、body 上限 64KB、只接受 https
- 面板: 密码登录(密码与 secret 做 SHA-256 后定长比较)、
  Session Cookie(HttpOnly/Secure/SameSite=Lax, 随机 32 字节, KV 存储, 7 天过期)、
  登录限流(同一 IP 5 次失败锁 5 分钟)
- 响应头: CSP(不加载任何外部资源)、X-Frame-Options DENY、nosniff、no-referrer、no-store
- Token 与面板密码只存在 Cloudflare Secret 里, 不进代码、不进日志、不进任何响应;
  agent 的 token 只放在 VPS 上 600 权限的 /etc/vps-probe/env

## 轮换凭证

```bash
cd worker
printf '%s' '<新token>' | python3 ~/workspace/custom-connectors/custom.cloudflare/bin/wrangler-auth.py secret put AGENT_TOKEN
printf '%s' '<新密码>' | python3 ~/workspace/custom-connectors/custom.cloudflare/bin/wrangler-auth.py secret put DASHBOARD_PASSWORD
# 换 token 后要在各 VPS 上更新 /etc/vps-probe/env 并重启 agent:
# systemctl restart vps-probe-agent
```

## 重新部署

```bash
cd worker
python3 ~/workspace/custom-connectors/custom.cloudflare/bin/wrangler-auth.py deploy
```

## 待做(以后)

- 回程线路: 需要国内节点定时 traceroute 回来并上报
- 掉线告警: Worker 定时任务检查 lastSeen, 超时发通知
- 历史曲线: KV 存 24 小时采样点, 面板画小图
