#!/usr/bin/env bash
# Agent 发新版: 编译 amd64 + arm64, 发 GitHub Release, 各 VPS 重跑安装命令即升级。
# 用法: ./release.sh v1.1.3 "更新说明"
set -euo pipefail
cd "$(dirname "$0")"
VERSION="${1:?用法: ./release.sh vX.Y.Z [更新说明]}"
NOTES="${2:-$VERSION}"
bash agent/build.sh
gh release create "$VERSION" dist/vps-probe-agent-linux-amd64 dist/vps-probe-agent-linux-arm64 --repo wzlinbin/vps-probe --title "$VERSION" --notes "$NOTES"
echo "已发 $VERSION, 各 VPS 重跑安装命令升级。"
