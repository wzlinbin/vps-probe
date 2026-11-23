#!/bin/bash
# 编译 agent: 静态二进制, amd64 + arm64
set -euo pipefail
cd "$(dirname "$0")"
export GO=/home/hatch/workspace/.tools/go/bin/go
export CGO_ENABLED=0
mkdir -p ../dist
GOOS=linux GOARCH=amd64 $GO build -trimpath -ldflags="-s -w" -o ../dist/vps-probe-agent-linux-amd64 .
GOOS=linux GOARCH=arm64 $GO build -trimpath -ldflags="-s -w" -o ../dist/vps-probe-agent-linux-arm64 .
ls -la ../dist/
file ../dist/* 2>/dev/null || true
