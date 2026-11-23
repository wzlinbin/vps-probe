#!/bin/bash
# 在 VPS 上安装 vps-probe-agent (需 root)
# 用法: sudo bash install.sh <Worker地址> <上报token> [节点id] [显示名] [运营商ct/cu/cm] [回程目标, 如 la:1.2.3.4]
# 节点 id 不写则按主机名自动生成; 显示名也可在面板上改
# 缺失的 traceroute/ping/nexttrace 会自动尝试安装; 本地没有二进制时自动从 GitHub Release 下载
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行: sudo bash $0 ..." >&2
  exit 1
fi

URL="${1:-}"
TOKEN="${2:-}"
NODE="${3:-}"
NAME="${4:-}"
CARRIER="${5:-}"
RETURNS="${6:-}"
if [ -z "$URL" ] || [ -z "$TOKEN" ]; then
  echo "用法: sudo bash $0 <Worker地址> <上报token> [节点id] [显示名] [运营商ct/cu/cm] [回程目标, 如 la:1.2.3.4]" >&2
  exit 1
fi
# 节点 id 不写则按主机名自动生成(小写、非法字符变连字符、最长 32 位)
if [ -z "$NODE" ]; then
  NODE="$(hostname 2>/dev/null | tr '[:upper:]' '[:lower:]' | sed -E -e 's/[^a-z0-9]+/-/g' -e 's/^-//' -e 's/-$//' | cut -c1-32 | sed -e 's/-$//')"
  if [ -z "$NODE" ]; then NODE="node-$(head -c 3 /dev/urandom | od -An -tx1 | tr -d ' \n')"; fi
  echo "未指定节点 id, 已按主机名自动生成: $NODE"
fi
# 重装时没给显示名, 沿用上次的
if [ -z "$NAME" ] && [ -f /etc/vps-probe/env ]; then
  NAME="$(grep '^PROBE_NAME=' /etc/vps-probe/env 2>/dev/null | cut -d= -f2- || true)"
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
  # 本地没有二进制, 从 GitHub Release 下载(用 latest, 重跑即升级到最新版, 不要写死版本号)
  RELEASE_BASE="https://github.com/wzlinbin/vps-probe/releases/latest/download"
  echo "本地没有 $BIN, 从 $RELEASE_BASE 下载..."
  command -v curl >/dev/null || { echo "需要 curl 才能下载二进制" >&2; exit 1; }
  BIN_PATH="$(mktemp)"
  curl -fsSL "$RELEASE_BASE/$BIN" -o "$BIN_PATH" || { echo "下载失败, 请检查网络或 Release 是否存在" >&2; exit 1; }
  chmod 755 "$BIN_PATH"
fi

# 缺失的软件自动安装 (traceroute 测去程线路, ping 测三网延迟)
install_deps() {
  local need=""
  command -v traceroute >/dev/null || need="$need traceroute"
  command -v ping >/dev/null || need="$need ping"
  [ -z "$need" ] && return 0
  echo "缺少:$need, 尝试自动安装..."
  if command -v apt-get >/dev/null; then
    (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq traceroute iputils-ping) || echo "警告: 自动安装失败, 请手工安装:$need (去程线路/延迟将显示为空)"
  elif command -v dnf >/dev/null; then
    dnf install -y -q traceroute iputils || echo "警告: 自动安装失败, 请手工安装:$need"
  elif command -v yum >/dev/null; then
    yum install -y -q traceroute iputils || echo "警告: 自动安装失败, 请手工安装:$need"
  elif command -v apk >/dev/null; then
    apk add --no-cache traceroute iputils || echo "警告: 自动安装失败, 请手工安装:$need"
  else
    echo "警告: 未找到包管理器, 请手工安装:$need (去程线路/延迟将显示为空)"
  fi
  command -v traceroute >/dev/null || echo "提示: traceroute 仍未安装, 去程线路将显示为未知"
  command -v ping >/dev/null || echo "提示: ping 仍未安装, 三网延迟将显示为空"
}
install_deps

# nexttrace(逐跳 ASN 判线, v1.7.6 已验证 --json 结构); 装不上只警告, agent 回落到 traceroute+网段表
install_nexttrace() {
  command -v nexttrace >/dev/null 2>&1 && return 0
  local arch tmp
  case "$(uname -m)" in
    x86_64|amd64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) echo "提示: 不支持的架构 $(uname -m), 不装 nexttrace, 线路检测回落到 traceroute+网段表" >&2; return 0 ;;
  esac
  tmp="$(mktemp)"
  if curl -fsSL --connect-timeout 10 --max-time 90 -o "$tmp" "https://github.com/nxtrace/NTrace-core/releases/download/v1.7.6/nexttrace_linux_${arch}" 2>/dev/null && [ -s "$tmp" ]; then
    cp "$tmp" /usr/local/bin/nexttrace && chmod 0755 /usr/local/bin/nexttrace && echo "nexttrace 已安装 (v1.7.6)"
  else
    echo "警告: nexttrace 下载失败, 线路检测回落到 traceroute+网段表" >&2
  fi
  rm -f "$tmp"
}
install_nexttrace

install -m 755 "$BIN_PATH" /usr/local/bin/vps-probe-agent

mkdir -p /etc/vps-probe /var/lib/vps-probe
{
  echo "PROBE_URL=$URL/api/push"
  echo "PROBE_TOKEN=$TOKEN"
  echo "PROBE_NODE=$NODE"
  [ -n "$NAME" ] && echo "PROBE_NAME=$NAME"
  [ -n "$CARRIER" ] && echo "PROBE_CARRIER=$CARRIER"
  [ -n "$RETURNS" ] && echo "PROBE_RETURN_TARGETS=$RETURNS"
} > /etc/vps-probe/env
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
systemctl enable vps-probe-agent
systemctl restart vps-probe-agent
sleep 3
systemctl is-active --quiet vps-probe-agent || { echo "服务启动失败, 查看日志:"; journalctl -u vps-probe-agent -n 30 --no-pager; exit 1; }
echo "== 安装完成, 服务运行中 =="
journalctl -u vps-probe-agent -n 5 --no-pager
echo "查看实时日志: journalctl -u vps-probe-agent -f"
echo "卸载: systemctl disable --now vps-probe-agent; rm /usr/local/bin/vps-probe-agent /etc/systemd/system/vps-probe-agent.service; rm -rf /etc/vps-probe /var/lib/vps-probe"
