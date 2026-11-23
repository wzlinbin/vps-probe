# VPS 探针 (vps-probe)

自建的轻量 VPS 监控面板：Agent 采数据 → Cloudflare Worker 收数据、存 KV → 面板展示。
面板地址：https://vps-probe.wzlinbin.workers.dev

## 架构

```
VPS 上的 Go agent ──每 30 秒──▶ Cloudflare Worker ──▶ KV (vps-probe-kv)
                                          ▲                     │
                                          │                     ▼
国内 boce 探针 ──去程探测──▶ Cloudflare Workflow ──▶ KV ──▶ 面板 (浏览器)
```

- **回程**（VPS → 国内）：agent 自己用 nexttrace 测到杭州目标，30 秒上报一次。
- **去程**（国内 → VPS）：Cloudflare Workflow 调 boce.aliyun.com 的国内探针做 traceroute，测完写 KV，面板只读缓存。
- agent 本身不监听任何端口，只出站 HTTPS。

## 目录结构

```
vps-probe/
  agent/                 # VPS 上跑的 agent (Go, 零依赖, 静态二进制)
    main.go              # 采集 + 上报 + 回程线路探测
    main_test.go         # 单测
    cn2gt_test.go        # CN2 GT/GIA 与三段判线单测
    go.mod
    build.sh             # 交叉编译 amd64 + arm64 到 dist/
    install.sh           # 在 VPS 上一键安装 (systemd)
  worker/                # Cloudflare Worker (面板 + API) + Workflow (去程探测)
    src/worker.js        # 面板 + API + 登录页 (单文件, 无外部资源)
    src/boce-workflow.js # 去程探测 Workflow (BoceWorkflow)
    wrangler.toml        # KV 绑定 PROBE_KV + Workflow 绑定 BOCE_WORKFLOW
  boce-probe/            # 参考实现 (Python 版去程探测, 已迁到 Workflow, 不再运行)
    probe.py
  dist/                  # 编译好的二进制 (发 Release 用)
  README.md
```

## Agent 采集内容

- **CPU** 使用率、loadavg、**内存**、**硬盘**、系统 uptime。
- **流量**：速率 + 当月累计（北京时间，每月 1 日 0 点自动清零；VPS 重启不丢当月累计；状态文件 `/var/lib/vps-probe/state.json`）。
- **三网 ping**：每运营商多个目标，主目标 100% 丢包自动换备用（电信 114.114.114.114 → 202.96.128.86 → 61.139.2.69，联通 123.125.81.6 → 210.21.196.6，移动 211.136.17.107 → 120.196.165.24）。延迟优先 TCP 建连测 80 端口，ICMP 回落。
- **回程线路**：agent 用 nexttrace 测到杭州目标（每运营商 2 个 IP 互为备份：电信 115.239.211.112 / 122.224.186.100，联通 101.68.73.100 / 221.12.1.227，移动 223.95.78.100 / 112.17.0.100），取首个能分类的。测不出不覆盖好结果；有结果 24 小时一测，无结果 5 分钟重试；面板“立即检测”可强制重测。
- **去程线路**：agent 不测，由 Workflow 的 boce 探针测（见下节）。

Agent 每 30 秒 POST 一次 JSON 到 `https://vps-probe.wzlinbin.workers.dev/api/push`。

## 线路判线

判线分两步，逐跳 ASN 优先、无 ASN 回落网段表：

1. **nexttrace 逐跳 ASN**：每跳先看 ASN（4134 163、4809 CN2、9929 联通 A 网、4837 联通 169、58807 CMIN2、58453 CMI、9808 移动普通 + 各省 CMNET、23764 CTGNet、10099 CUG、4538 CERNET、7641 CBN、37963/45102 阿里云、45090/132203 腾讯云、55990 华为云）。
2. **无 ASN 回落 IP 网段表**：59.43 → CN2、202.97 → 163、218.30.（除 218.30.62.0/23 CTGNet 外）→ 163 等；223.120 按第三段区分（0–127 CMI、128–255 CMIN2）。网段表见 `agent/main.go` 的 `routePrefixes`（与 `worker/src/boce-workflow.js` 的 `ROUTE_PREFIXES` 同步）。

**关键规则（扫完全部跳点再判，不能只取第一个能判出的跳点）：**

- **CN2 GT（半程）与 CN2 GIA（全程）**：163 与 CN2 都出现时看先后。163 在先、CN2 在后是 CN2 GT（例：218.30.48.73 AS4134 洛杉矶出口 → 59.43.x.x 上海 CN2）；CN2 在先是 CN2 GIA；仅其一取其一。其他运营商取跳点顺序中最先出现的线路。
- **三段**：每条线路除标签外还算三段（面板标签下小字显示）：
  - **跨境路由**：入境前后骨干变化，如 `163 → CN2`（前后相同则只写一个，如 `CN2`）。
  - **国内路由**：入境后第一个骨干标签，如 `CN2`。
  - （出口节点 IP 仍在算，但面板不显示。）
  - 入境点 = 第一个能判出线路且非 `218.30.` 的跳点（`218.30.` 可为美国出口，如 218.30.48.73，靠前缀分不出国内外，须排除）。
- 面板显示 ASN + 线路名，不显示城市。如 `163` → `AS4134 普通 163 骨干网`，`CN2` → `AS4809 CN2 GIA`，`CN2 GT` → `AS4134/4809 CN2 GT`，`9929` → `AS9929 联通 A 网`，`9808` → `AS9808 移动普通骨干网`。

## 在 VPS 上安装

不用手工传文件，在 VPS 上一条命令（会从 GitHub 拉 install.sh，再自动下对应架构的二进制）：

```bash
curl -fsSL https://raw.githubusercontent.com/wzlinbin/vps-probe/main/agent/install.sh -o install.sh && sudo bash install.sh https://vps-probe.wzlinbin.workers.dev <上报token> [节点id] [显示名]
# 例如: curl -fsSL https://raw.githubusercontent.com/wzlinbin/vps-probe/main/agent/install.sh -o install.sh && sudo bash install.sh https://vps-probe.wzlinbin.workers.dev <token> la "洛杉矶"
```

- 节点 id 可省，按主机名自动生成；只允许小写字母、数字、连字符，1–32 位。
- 显示名（第 4 个参数）是 agent 上报的初始名字；也可以直接在面板上改：每台机器下方设置栏第一个输入框就是备注，保存后立即生效，面板上的备注优先于命令里给的名字。
- install.sh 后面还有两个可选参数 `[运营商 ct/cu/cm] [回程目标, 如 la:1.2.3.4]`：只在国内机器上跑 agent、要它 traceroute 测到指定 VPS 的线路时才用；主流程（回程测杭州、去程走 boce）不需要填。
- 重跑安装命令即原地升级并重启服务（升级 agent 时用同一条命令即可）。
- install.sh 会自动安装缺失的 traceroute/ping/nexttrace（apt/dnf/yum/apk），装不上只警告、不中断安装。
- install.sh 会：装二进制到 /usr/local/bin、写 600 权限的 `/etc/vps-probe/env`、写 systemd unit（`vps-probe-agent`，Restart=always、开机自启）、干跑一次验证采集、enable 并启动。
- 查看日志：`journalctl -u vps-probe-agent -f`
- 忘记 token：`sudo grep PROBE_TOKEN /etc/vps-probe/env`
- 卸载：`systemctl disable --now vps-probe-agent; rm /usr/local/bin/vps-probe-agent /etc/systemd/system/vps-probe-agent.service; rm -rf /etc/vps-probe /var/lib/vps-probe`

## 面板功能

- 登录后查看各节点：CPU/内存/硬盘（圆盘指针仪表，绿 <60 / 黄 <85 / 红 ≥85）、流量（当月总量 + 配额进度条 + 实时速率与累计）、三网延迟条、去程/回程线路（含跨境路由/国内路由三段小字）。
- 顶部导航条：各节点状态点 + 名称胶囊，点即跳转定位到对应卡片并描边高亮 1.5 秒。
- 每个节点可设置：备注名、流量配额 GB、到期日、月费（面板“保存设置”）。到期与月费拼成一段红色显示，文案为“剩余 X 天 · 续费金额：Y”。
- 顶栏“＋ 新增节点”弹窗：填节点 id/显示名，实时生成带 token 的安装命令 + 复制按钮。
- 删除节点：每卡片红色“删除节点”按钮，确认后删 KV 记录。注意：agent 仍在跑的节点删了 30 秒内重现，只对死节点真正有效。
- 每卡片“立即检测”按钮：强制 agent 下轮重测回程线路（约 1 分钟更新）。
- 在线判断：120 秒内有上报算在线；运行时间显示 agent 上报的系统 uptime。
- 每 5 秒自动刷新；设置表单正在输入时不重建卡片，草稿不会被刷新清空。

## 去程探测（boce Workflow）

去程用 boce.aliyun.com（阿里云网站运维检测）的国内探针做 traceroute，免登录、无验证码。

- **运行方式**：Cloudflare Workflow `vps-probe-boce`（单例实例 `boce-agent`，代码 `worker/src/boce-workflow.js`），常驻循环：测一轮 → 按结果睡觉 → 醒来再测。管理：面板登录后 POST `/api/boce/start` 启动、GET `/api/boce/status` 查状态；或 `wrangler workflows trigger/instances`。
- **探测节奏**：测出正常线路 → 7 天后再测；没测出结果 → 5 分钟后重试。“未知”（有跳点但判不出线路）不算正常结果，也按 5 分钟重试。KV `return:` TTL 8 天，面板接受 8 天内的值。
- **探针选择**：杭州优先（电信/联通/移动各 1 个杭州探针），备选按 杭州 → 浙江 → 江苏/上海 三档依次试（浙江移动探针常全空，会落到上海）。每运营商只测 1 个探针。
- **判线**：与 agent 同一套网段表（见上节），去程方向同样分 CN2 GT/GIA；三段也一样算（国内骨干按 163/CN2 先后分 GT/GIA；出口 = 最后国内跳点 IP；跨境 = 最后国内标签 → 海外）。
- **注意**：boce 探针是国内节点，只能测去程（国内 → VPS），不能测回程；boce 返回的 ipGeoMap 只有归属地和运营商名、无 ASN，所以去程只能靠 IP 网段表判线。

## 安全性

- **上报**：Bearer token 鉴权（与 Worker secret 做 SHA-256 后定长比较）、严格 schema 校验（字段白名单、数值范围、时间戳与服务器相差 < 1 小时）、10 秒/节点限流、body 上限 64KB、只接受 https。
- **面板**：密码登录（密码与 secret 做 SHA-256 后定长比较）、Session Cookie（HttpOnly/Secure/SameSite=Lax，随机 32 字节，KV 存储，7 天过期）、登录限流（同一 IP 5 次失败锁 5 分钟）。
- **面板取 token**：登录后 GET `/api/agent-token` 可取上报 token，用于“新增节点”弹窗生成安装命令。token 现在可被任何能登录面板的人取到。
- **响应头**：CSP（不加载任何外部资源）、X-Frame-Options DENY、nosniff、no-referrer、no-store。
- Token 与面板密码只存在 Cloudflare Secret 里，不进代码、不进日志、不进任何响应；agent 的 token 只放在 VPS 上 600 权限的 `/etc/vps-probe/env`。

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
# Worker + Workflow 一起部署 (wrangler.toml 里配好)
cd worker
python3 ~/workspace/custom-connectors/custom.cloudflare/bin/wrangler-auth.py deploy
# Workflow 代码改了要重启实例才生效:
python3 ~/workspace/custom-connectors/custom.cloudflare/bin/wrangler-auth.py workflows instances restart vps-probe-boce boce-agent
```

```bash
# Agent 发新版 (改了 agent/main.go 才需要)
cd ~/workspace/vps-probe
bash agent/build.sh   # 交叉编译 amd64 + arm64 到 dist/
gh release create vX.Y.Z dist/vps-probe-agent-linux-amd64 dist/vps-probe-agent-linux-arm64 --repo wzlinbin/vps-probe --title "vX.Y.Z ..." --notes "..."
# 注意: Release 的 asset 名必须与 install.sh 的 BIN 一致
# (vps-probe-agent-linux-amd64 / vps-probe-agent-linux-arm64),
# install.sh 的下载地址是 releases/latest/download, 不要写死版本号。
# 然后在各 VPS 重跑安装命令升级。
```

## 常用命令

```bash
# 看 KV 里所有键
python3 ~/workspace/custom-connectors/custom.cloudflare/bin/wrangler-auth.py kv key list --namespace-id 02c6577154654aec8bb7a0436d0e3ca3 --remote
# 看某节点最新上报
python3 ~/workspace/custom-connectors/custom.cloudflare/bin/wrangler-auth.py kv key get "node:la:latest" --namespace-id 02c6577154654aec8bb7a0436d0e3ca3 --remote
# 看某节点去程
python3 ~/workspace/custom-connectors/custom.cloudflare/bin/wrangler-auth.py kv key get "return:la:ct" --namespace-id 02c6577154654aec8bb7a0436d0e3ca3 --remote
# 删某键 (KV 删除/读取必须加 --remote)
python3 ~/workspace/custom-connectors/custom.cloudflare/bin/wrangler-auth.py kv key delete "return:la:ct" --namespace-id 02c6577154654aec8bb7a0436d0e3ca3 --remote
# 看 Workflow 实例状态
python3 ~/workspace/custom-connectors/custom.cloudflare/bin/wrangler-auth.py workflows instances describe vps-probe-boce boce-agent
```

## 版本历史

- **v1.0.8**：回程目标改为杭州（每运营商 2 个 IP 互为备份）。
- **v1.0.9**：流量累计改为当月累计、次月重置（北京时间）。
- **v1.1.0**：判线表按联网核对重改（223.120 分 CMI/CMIN2、CMIN2 前缀收窄、补省 CMNET ASN 与非三网标签等）；去程从 VM systemd 迁到 Cloudflare Workflow。
- **v1.1.1**：判线改扫完全部跳点，电信分 CN2 GT（半程）/ CN2 GIA（全程）；补 218.30.（除 CTGNet 62 段外）为 163。
- **v1.1.2**：去程/回程各显示三段（出口节点 / 跨境路由 / 国内路由）；面板线路显示 ASN + 线路名，不显示城市。
