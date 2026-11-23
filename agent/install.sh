#!/bin/bash
# 在 VPS 上安装 vps-probe-agent (需 root)
# 用法: sudo bash install.sh <Worker地址> <上报token> <节点id>
# 示例: sudo bash install.sh https://vps-probe.xxx.workers.dev <token> la
# 二进制文件须与本脚本在同一目录: vps-probe-agent-linux-amd64 或 -arm64
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行: sudo bash $0 ..." >&2
  exit 1
fi

URL="${1:-}"
TOKEN="${2:-}"
NODE="${3:-}"
if [ -z "$URL" ] || [ -z "$TOKEN" ] || [ -z "$NODE" ]; then
  echo "用法: sudo bash $0 <Worker地址> <上报token> <节点id>" >&2
  exit 1
fi
case "$URL" in
  https://*) ;;
  *) echo "Worker 地址必须是 https://" >&2; exit 1 ;;
esac
case "$NODE" in
  *[!a-z0-9-]*) echo "节点 id 只允许小写字母、数字、连字符" >&2; exit 1 ;;
esac

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64) BIN="vps-probe-agent-linux-amd64" ;;
  aarch64|arm64) BIN="vps-probe-agent-linux-arm64" ;;
  *) echo "不支持的架构: $ARCH" >&2; exit 1 ;;
esac
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BIN_PATH="$SCRIPT_DIR/$BIN"
if [ ! -f "$BIN_PATH" ]; then
  # 本地没有二进制, 从 GitHub Release 下载
  RELEASE_BASE="https://github.com/wzlinbin/vps-probe/releases/download/v1.0.0"
  echo "本地没有 $BIN, 从 $RELEASE_BASE 下载..."
  command -v curl >/dev/null || { echo "需要 curl 才能下载二进制" >&2; exit 1; }
  BIN_PATH="$(mktemp)"
  curl -fsSL "$RELEASE_BASE/$BIN" -o "$BIN_PATH" || { echo "下载失败, 请检查网络或 Release 是否存在" >&2; exit 1; }
  chmod 755 "$BIN_PATH"
fi

command -v ping >/dev/null || echo "警告: 未找到 ping, 三网延迟将显示为空"
command -v traceroute >/dev/null || echo "警告: 未找到 traceroute, 去程线路将显示为未知 (apt install traceroute / yum install traceroute)"

install -m 755 "$BIN_PATH" /usr/local/bin/vps-probe-agent

mkdir -p /etc/vps-probe /var/lib/vps-probe
cat > /etc/vps-probe/env <<EOF
PROBE_URL=$URL/api/push
PROBE_TOKEN=$TOKEN
PROBE_NODE=$NODE
EOF
chmod 600 /etc/vps-probe/env

cat > /etc/systemd/system/vps-probe-agent.service <<'EOF'
[Unit]
Description=VPS Probe Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/etc/vps-probe/env
ExecStart=/usr/local/bin/vps-probe-agent
Restart=always
RestartSec=5
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/var/lib/vps-probe

[Install]
WantedBy=multi-user.target
EOF

echo "== 干跑验证采集 =="
/usr/local/bin/vps-probe-agent -once | head -30

systemctl daemon-reload
systemctl enable --now vps-probe-agent
sleep 3
systemctl is-active --quiet vps-probe-agent || { echo "服务启动失败, 查看日志:"; journalctl -u vps-probe-agent -n 30 --no-pager; exit 1; }
echo "== 安装完成, 服务运行中 =="
journalctl -u vps-probe-agent -n 5 --no-pager
echo "查看实时日志: journalctl -u vps-probe-agent -f"
echo "卸载: systemctl disable --now vps-probe-agent; rm /usr/local/bin/vps-probe-agent /etc/systemd/system/vps-probe-agent.service; rm -rf /etc/vps-probe /var/lib/vps-probe"
