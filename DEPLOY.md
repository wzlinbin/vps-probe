# vps-probe 部署 (极简版)

## 点按钮部署: 不用敲命令

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/wzlinbin/vps-probe/tree/main/worker)

点一下，Cloudflare 会从 GitHub 拉代码、自动创建 KV、部署 Worker。部署时它会让你填两个 secret（`AGENT_TOKEN` 上报 token、`DASHBOARD_PASSWORD` 面板登录密码），填完就能用。去程探测的 Workflow 需要 Workers Paid 套餐（已有）。

注意：按钮是全新部署一台 Worker，现有那台和它的数据不受影响；部署时 Worker 名字可以改，改了就是另一台。

## 命令行部署

都在项目根目录运行，不用 `cd` 到别处：

```bash
cd ~/workspace/vps-probe
```

## 日常更新: 一条命令

```bash
./deploy.sh
```

部署 Worker + Workflow, 并重启 Workflow 实例让新代码生效。
地址: https://vps-probe.wzlinbin.workers.dev

## 首次部署: 先设两个密码

面板密码和上报 token 各一个, 都存在 Cloudflare Secret 里, 不在代码里。
`set-secret.sh` 会提示输入, 不回显、不进 shell 历史。

```bash
./set-secret.sh DASHBOARD_PASSWORD   # 面板登录密码
./set-secret.sh AGENT_TOKEN          # agent 上报 token, 先用 openssl rand -hex 32 生成一个
./deploy.sh
```

也可以在 Cloudflare 仪表盘上点: Workers & Pages → vps-probe → Settings → Variables → Add Secret, 名字填上面两个。

首次部署后, 去程探测需启动一次: 登录面板后调一次 `POST /api/boce/start` (只做一次, 之后重启自动恢复)。

## Agent 发新版

```bash
./release.sh v1.1.3 "更新说明"
```

编译 amd64 + arm64, 发 GitHub Release。发完在各 VPS 重跑安装命令升级。

## 忘了密码 / 怀疑 token 泄露

```bash
./set-secret.sh DASHBOARD_PASSWORD   # 重置面板密码, 立即生效
./set-secret.sh AGENT_TOKEN          # 换 token, 再到各 VPS 更新 /etc/vps-probe/env 并重启 agent
```

详细说明 (token 存在哪、轮换步骤、注意事项) 见 README.md 的“上报 Token 的设置与管理”一节。
