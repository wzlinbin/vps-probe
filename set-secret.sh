#!/usr/bin/env bash
# 存一个 Cloudflare Secret, 输入不回显、不进 shell 历史。
# 用法: ./set-secret.sh AGENT_TOKEN
#      ./set-secret.sh DASHBOARD_PASSWORD
set -euo pipefail
NAME="${1:?用法: ./set-secret.sh <名字>, 如 AGENT_TOKEN 或 DASHBOARD_PASSWORD}"
read -r -s -p "输入 $NAME 的新值 (不回显, 输完回车): " VALUE
echo
[ -n "$VALUE" ] || { echo "值不能为空"; exit 1; }
cd "$(dirname "$0")/worker"
printf '%s' "$VALUE" | python3 "$HOME/workspace/custom-connectors/custom.cloudflare/bin/wrangler-auth.py" secret put "$NAME"
echo "$NAME 已更新, 立即生效。"
