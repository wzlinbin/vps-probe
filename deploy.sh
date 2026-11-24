#!/usr/bin/env bash
# vps-probe 一键部署: Worker + Workflow, 然后重启 Workflow 实例让新代码生效。
# 用法: 在项目根目录运行 ./deploy.sh (不用 cd 到别处)
set -euo pipefail
cd "$(dirname "$0")/worker"
WRANGLER=(python3 "$HOME/workspace/custom-connectors/custom.cloudflare/bin/wrangler-auth.py")
"${WRANGLER[@]}" deploy
# Workflow 代码改了要重启实例才生效; 首次部署还没有实例, 失败不用管。
"${WRANGLER[@]}" workflows instances restart vps-probe-boce boce-agent || true
echo "部署完成: https://vps-probe.wzlinbin.workers.dev"
