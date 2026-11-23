// vps-probe-agent: 轻量 VPS 探针 agent，零外部依赖，只用 Go 标准库。
//
// 采集: CPU、loadavg、内存、硬盘、流量(速率+累计)、uptime,
// 三网 ping 延迟/丢包、去程 traceroute 线路分类(163/9929/CMIN2/4837)。
// 上报: 每 interval 秒向 Worker POST 一次 JSON，Bearer token 鉴权。
// 本身不监听任何端口，只出站 HTTPS。
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ---------- 配置 ----------

type config struct {
	URL           string
	Token         string
	Node          string
	Name          string
	Carrier       string
	ReturnTargets string
	Interval      time.Duration
	RouteInterval time.Duration
	Once          bool
	AllowHTTP     bool
	StateDir      string
}

func loadConfig() config {
	var c config
	flag.StringVar(&c.URL, "url", "", "Worker 上报地址, 如 https://vps-probe.<子域>.workers.dev/api/push")
	flag.StringVar(&c.Token, "token", "", "上报 token (也可走环境变量 PROBE_TOKEN)")
	flag.StringVar(&c.Node, "node", "", "节点 id, 如 la (也可走环境变量 PROBE_NODE)")
	flag.StringVar(&c.Name, "name", "", "节点显示名, 如 洛杉矶 (也可走环境变量 PROBE_NAME, 不填则显示节点 id)")
	flag.StringVar(&c.Carrier, "carrier", "", "本机所在运营商 ct/cu/cm, 用于回程探测 (也可走环境变量 PROBE_CARRIER)")
	flag.StringVar(&c.ReturnTargets, "return-targets", "", "回程探测目标, 如 la:1.2.3.4,node2:5.6.7.8 (也可走环境变量 PROBE_RETURN_TARGETS)")
	flag.DurationVar(&c.Interval, "interval", 30*time.Second, "上报间隔")
	flag.DurationVar(&c.RouteInterval, "route-interval", 5*time.Minute, "线路探测间隔(去程/回程), 如 5m")
	flag.BoolVar(&c.Once, "once", false, "只采集一次并打印 JSON，不上报")
	flag.BoolVar(&c.AllowHTTP, "allow-http", false, "允许 http 上报(仅本地测试)")
	flag.StringVar(&c.StateDir, "state-dir", "/var/lib/vps-probe", "累计流量状态文件目录")
	flag.Parse()

	if v := os.Getenv("PROBE_URL"); v != "" && c.URL == "" {
		c.URL = v
	}
	if v := os.Getenv("PROBE_TOKEN"); v != "" && c.Token == "" {
		c.Token = v
	}
	if v := os.Getenv("PROBE_NODE"); v != "" && c.Node == "" {
		c.Node = v
	}
	if v := os.Getenv("PROBE_NAME"); v != "" && c.Name == "" {
		c.Name = v
	}
	if v := os.Getenv("PROBE_CARRIER"); v != "" && c.Carrier == "" {
		c.Carrier = v
	}
	if v := os.Getenv("PROBE_RETURN_TARGETS"); v != "" && c.ReturnTargets == "" {
		c.ReturnTargets = v
	}
	if v := os.Getenv("PROBE_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.Interval = d
		}
	}
	if v := os.Getenv("PROBE_ROUTE_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			c.RouteInterval = d
		}
	}
	return c
}

// ---------- 上报结构 ----------

type pingResult struct {
	Avg  *float64 `json:"avg"`  // ms, 测不到为 null
	Loss *float64 `json:"loss"` // %, 测不到为 null
}

type report struct {
	Node         string                        `json:"node"`
	Name         string                        `json:"name,omitempty"`
	Carrier      string                        `json:"carrier,omitempty"`
	ReturnRoutes map[string]string             `json:"return_routes,omitempty"`
	TS           int64                         `json:"ts"`
	Hostname     string                        `json:"hostname"`
	Uptime       int64                         `json:"uptime"` // 秒
	CPU          float64                       `json:"cpu"`    // %
	Load         [3]float64                    `json:"load"`
	MemTotal     uint64                        `json:"mem_total"`
	MemUsed      uint64                        `json:"mem_used"`
	DiskTotal    uint64                        `json:"disk_total"`
	DiskUsed     uint64                        `json:"disk_used"`
	NetRx        uint64                        `json:"net_rx"`      // 累计接收字节(跨重启累计)
	NetTx        uint64                        `json:"net_tx"`      // 累计发送字节(跨重启累计)
	NetRxRate    uint64                        `json:"net_rx_rate"` // B/s
	NetTxRate    uint64                        `json:"net_tx_rate"` // B/s
	Ping         map[string]*pingResult        `json:"ping"`        // ct/cu/cm
	Route        map[string]map[string]*string `json:"route"`       // ct/cu/cm -> sh/gz/bj -> 163/CN2/9929/4837/CMIN2/9808/未知
}

// 三网探测目标(各家常用 DNS, 可被环境变量覆盖 PROBE_PING_CT/CU/CM)
var pingTargets = map[string][]string{
	// 每运营商多个目标: 主目标 100% 丢包时自动换备用目标重测
	"ct": {"114.114.114.114", "202.96.128.86", "61.139.2.69"}, // 电信
	"cu": {"123.125.81.6", "210.21.196.6"},                    // 联通
	"cm": {"211.136.17.107", "120.196.165.24"},                // 移动
}

// 去程线路探测目标: 每运营商 3 个城市骨干节点, 用于区分线路类型
// (电信 163/CN2, 联通 4837/9929, 移动 9808/CMIN2)。
var routeTargets = map[string]map[string]string{
	"ct": {"sh": "101.95.120.1", "gz": "14.215.116.1", "bj": "219.141.136.10"},     // 电信 上海/广州/北京
	"cu": {"sh": "112.65.63.1", "gz": "210.21.196.6", "bj": "123.125.99.1"},        // 联通 上海/广州/北京
	"cm": {"sh": "120.204.197.1", "gz": "120.196.165.24", "bj": "221.179.155.161"}, // 移动 上海/广州/北京
}

// ---------- 采集 ----------

type returnTarget struct{ node, ip string }

type collector struct {
	name          string
	carrier       string
	returnTargets []returnTarget
	prevCPU       cpuSample
	prevNet       netSample
	prevNetAt     time.Time
	statePath     string
	cumRx         uint64
	cumTx         uint64
	lastRx        uint64
	lastTx        uint64
	haveState     bool
	// 线路探测降频: 去程/回程每 routeInterval 才重测一次, 期间用缓存
	routeInterval time.Duration
	lastRoute     map[string]map[string]*string
	lastRet       map[string]string
	nextRoute     time.Time
}

type cpuSample struct {
	idle  uint64
	total uint64
}

func readCPU() (cpuSample, error) {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "cpu ") {
			f := strings.Fields(line)
			if len(f) < 5 {
				return cpuSample{}, fmt.Errorf("bad /proc/stat")
			}
			var total uint64
			for _, s := range f[1:] {
				v, err := strconv.ParseUint(s, 10, 64)
				if err != nil {
					return cpuSample{}, err
				}
				total += v
			}
			idle, _ := strconv.ParseUint(f[4], 10, 64)
			return cpuSample{idle: idle, total: total}, nil
		}
	}
	return cpuSample{}, fmt.Errorf("cpu line not found")
}

func (c *collector) cpuUsage() float64 {
	cur, err := readCPU()
	if err != nil {
		return 0
	}
	if c.prevCPU.total == 0 {
		// 首次: 1 秒内再采一次算差值
		time.Sleep(time.Second)
		cur2, err := readCPU()
		if err != nil {
			return 0
		}
		c.prevCPU = cur2
		dTotal := cur2.total - cur.total
		dIdle := cur2.idle - cur.idle
		if dTotal == 0 {
			return 0
		}
		return round1(100 * (1 - float64(dIdle)/float64(dTotal)))
	}
	dTotal := cur.total - c.prevCPU.total
	dIdle := cur.idle - c.prevCPU.idle
	c.prevCPU = cur
	if dTotal == 0 {
		return 0
	}
	return round1(100 * (1 - float64(dIdle)/float64(dTotal)))
}

func readLoad() [3]float64 {
	var out [3]float64
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return out
	}
	f := strings.Fields(string(b))
	for i := 0; i < 3 && i < len(f); i++ {
		out[i], _ = strconv.ParseFloat(f[i], 64)
	}
	return out
}

func readMem() (total, used uint64) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	var avail uint64
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(f[1], 10, 64)
		v *= 1024
		switch f[0] {
		case "MemTotal:":
			total = v
		case "MemAvailable:":
			avail = v
		}
	}
	if total == 0 {
		return 0, 0
	}
	if avail > total {
		avail = total
	}
	return total, total - avail
}

func readDisk() (total, used uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return 0, 0
	}
	total = st.Blocks * uint64(st.Bsize)
	free := st.Bfree * uint64(st.Bsize)
	if free > total {
		free = total
	}
	return total, total - free
}

type netSample struct {
	rx uint64
	tx uint64
}

func defaultIface() string {
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) >= 2 && f[1] == "00000000" {
			return f[0]
		}
	}
	return ""
}

func readNet() netSample {
	b, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return netSample{}
	}
	iface := defaultIface()
	var rx, tx uint64
	for _, line := range strings.Split(string(b), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		if name == "lo" {
			continue
		}
		if iface != "" && name != iface {
			continue
		}
		f := strings.Fields(parts[1])
		if len(f) < 16 {
			continue
		}
		r, _ := strconv.ParseUint(f[0], 10, 64)
		t, _ := strconv.ParseUint(f[8], 10, 64)
		rx += r
		tx += t
	}
	return netSample{rx: rx, tx: tx}
}

func readUptime() int64 {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f, _ := strconv.ParseFloat(strings.Fields(string(b))[0], 64)
	return int64(f)
}

// 累计流量持久化: 每轮把增量加进 state 文件, 重启/掉电也不丢。
type netState struct {
	CumRx  uint64 `json:"cum_rx"`
	CumTx  uint64 `json:"cum_tx"`
	LastRx uint64 `json:"last_rx"`
	LastTx uint64 `json:"last_tx"`
}

func (c *collector) loadState() {
	if c.statePath == "" {
		return
	}
	b, err := os.ReadFile(c.statePath)
	if err != nil {
		return
	}
	var s netState
	if json.Unmarshal(b, &s) == nil {
		c.cumRx, c.cumTx, c.lastRx, c.lastTx = s.CumRx, s.CumTx, s.LastRx, s.LastTx
		c.haveState = true
	}
}

func (c *collector) saveState() {
	if c.statePath == "" {
		return
	}
	s := netState{CumRx: c.cumRx, CumTx: c.cumTx, LastRx: c.lastRx, LastTx: c.lastTx}
	b, _ := json.Marshal(s)
	_ = os.MkdirAll(filepath.Dir(c.statePath), 0o755)
	tmp := c.statePath + ".tmp"
	if os.WriteFile(tmp, b, 0o644) == nil {
		_ = os.Rename(tmp, c.statePath)
	}
}

// ---------- ping / traceroute ----------

var (
	rttRe  = regexp.MustCompile(`rtt min/avg/max/mdev = [\d.]+/([\d.]+)/[\d.]+/[\d.]+ ms`)
	lossRe = regexp.MustCompile(`(\d+(?:\.\d+)?)% packet loss`)
)

func runCmd(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// runCmdSplit 与 runCmd 相同, 但 stdout/stderr 分开(nexttrace 的日志在 stderr, 不能混进要解析的 JSON)。
func runCmdSplit(ctx context.Context, name string, args ...string) (string, string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	return outBuf.String(), errBuf.String(), err
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 120 {
		s = s[:120]
	}
	return strings.TrimSpace(s)
}

func pingOne(target string) *pingResult {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	out, err := runCmd(ctx, "ping", "-c", "3", "-i", "0.2", "-W", "2", target)
	if err != nil && out == "" {
		return &pingResult{}
	}
	r := &pingResult{}
	if m := rttRe.FindStringSubmatch(out); m != nil {
		v, _ := strconv.ParseFloat(m[1], 64)
		r.Avg = &v
	}
	if m := lossRe.FindStringSubmatch(out); m != nil {
		v, _ := strconv.ParseFloat(m[1], 64)
		r.Loss = &v
	}
	return r
}

// TCP ping: 对目标端口做 TCP 建连, SYN-ACK 或 RST 都算收到回包(耗时即延迟),
// 超时未回包算丢包。ICMP 常被运营商/防火墙丢弃或限速, TCP 建连更接近真实流量。
func tcpPingOne(host, port string) (rttMs float64, ok bool) {
	start := time.Now()
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
	elapsed := time.Since(start).Seconds() * 1000
	if err == nil {
		conn.Close()
		return elapsed, true
	}
	// 对端 RST(端口关闭)说明已回包, 延迟有效
	if errors.Is(err, syscall.ECONNREFUSED) {
		return elapsed, true
	}
	return 0, false
}

// TCP ping 一个目标 3 次(80 端口), 返回平均延迟与丢包率; 3 次全丢返回 Avg=nil。
func tcpPingTarget(target string) *pingResult {
	const tries = 3
	var sum float64
	var okCount int
	for i := 0; i < tries; i++ {
		if rtt, ok := tcpPingOne(target, "80"); ok {
			sum += rtt
			okCount++
		}
	}
	r := &pingResult{}
	if okCount > 0 {
		avg := sum / float64(okCount)
		r.Avg = &avg
	}
	loss := float64(tries-okCount) / float64(tries) * 100
	r.Loss = &loss
	return r
}

// 逐个试目标, 第一个有回包的为准; 全不通则返回最后一个的结果(100% 丢包)。
// 每个目标先 TCP ping, 全丢再试 ICMP ping。
func pingWithFallback(targets []string) (*pingResult, string) {
	var last *pingResult
	used := targets[0]
	for _, t := range targets {
		p := tcpPingTarget(t)
		if p == nil || p.Avg == nil {
			p = pingOne(t)
		}
		last, used = p, t
		if p != nil && p.Avg != nil {
			break
		}
	}
	return last, used
}

// 线路分类: 按跳点 IP 的网段启发式判断, 命中即返回, 命中不了返回"未知"。
// 163: 202.97/16; CN2: 59.43/16; 9929: 219.158/16, 210.22/16;
// CMIN2: 223.96/16, 223.99/16, 211.136/16, 183.240/16, 120.196/16, 117.128/16;
// 4837(联通169): 218.105/16; 9808(移动普通): 221.179/16, 120.204/16。
var routePrefixes = []struct {
	prefix string
	label  string
}{
	{"202.97.", "163"}, {"59.43.", "CN2"},
	{"219.158.", "9929"}, {"210.22.", "9929"},
	{"223.96.", "CMIN2"}, {"223.99.", "CMIN2"}, {"211.136.", "CMIN2"},
	{"183.240.", "CMIN2"}, {"120.196.", "CMIN2"}, {"117.128.", "CMIN2"},
	{"218.105.", "4837"},
	{"221.179.", "9808"}, {"120.204.", "9808"},
}

func classifyIP(ip string) string {
	for _, p := range routePrefixes {
		if strings.HasPrefix(ip, p.prefix) {
			return p.label
		}
	}
	return ""
}

var hopRe = regexp.MustCompile(`(?m)^\s*\d+\s+(?:\S+\s+\()?(\d+\.\d+\.\d+\.\d+)\)?`)

func tracerouteOne(target string) *string {
	if _, err := exec.LookPath("traceroute"); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	// 先 ICMP 模式(-I, 沿途路由器回包率高), 命中不了再回落 UDP
	out, _ := runCmd(ctx, "traceroute", "-I", "-n", "-m", "20", "-w", "2", "-q", "1", target)
	if label := classifyRoute(out); label != "" {
		return &label
	}
	if ctx.Err() != nil {
		unknown := "未知"
		return &unknown
	}
	out, _ = runCmd(ctx, "traceroute", "-n", "-m", "20", "-w", "2", "-q", "1", target)
	if label := classifyRoute(out); label != "" {
		return &label
	}
	unknown := "未知"
	return &unknown
}

func classifyRoute(out string) string {
	seen := map[string]bool{}
	for _, m := range hopRe.FindAllStringSubmatch(out, -1) {
		ip := m[1]
		if seen[ip] {
			continue
		}
		seen[ip] = true
		if net.ParseIP(ip).IsPrivate() || strings.HasPrefix(ip, "10.") ||
			strings.HasPrefix(ip, "172.16.") || strings.HasPrefix(ip, "192.168.") {
			continue // 跳过内网跳点
		}
		if label := classifyIP(ip); label != "" {
			return label
		}
	}
	return ""
}

// 线路判断: 优先用 nexttrace 逐跳 ASN(比写死网段更根本, ASN 不会过时)。
// 4134 电信 163, 4809 电信 CN2, 9929 联通精品, 4837 联通 169,
// 58807 移动 CMIN2, 9808/56048/24400 移动普通(后两者是移动地方网 AS, 圈内统称 9808)。
var asnLabels = map[int]string{
	4134: "163", 4809: "CN2",
	9929: "9929", 4837: "4837",
	58807: "CMIN2",
	9808:  "9808", 56048: "9808", 24400: "9808",
}

// nexttrace --json 输出结构(只取需要的字段; 按 NTrace-core v1.7.6 源码核对:
// Result.Hops [][]Hop, Hop.Geo 是 *ipgeo.IPGeoData, 其 asnumber 如 "AS4134")。
type ntGeo struct {
	Asnumber string `json:"asnumber"`
}
type ntHop struct {
	Success bool            `json:"Success"`
	Address json.RawMessage `json:"Address"`
	Geo     *ntGeo          `json:"Geo"`
}
type ntResult struct {
	Hops [][]ntHop `json:"Hops"`
}

// nexttrace JSON 里 Hop.Address 是字符串 IP(无回包的跳点为 null)。
func ntHopIP(raw json.RawMessage) string {
	var ip string
	if len(raw) == 0 {
		return ""
	}
	if err := json.Unmarshal(raw, &ip); err != nil {
		return ""
	}
	return ip
}

// classifyNtHops 按 TTL 顺序取第一个能判出线路的跳点:
// 有 ASN 就按 ASN 判, 无 ASN 用跳点 IP 走网段表, 都判不出返回"未知"。
func classifyNtHops(hops [][]ntHop) string {
	for _, ttlHops := range hops {
		for _, h := range ttlHops {
			if !h.Success {
				continue
			}
			if h.Geo != nil && h.Geo.Asnumber != "" {
				num := strings.TrimPrefix(strings.TrimPrefix(h.Geo.Asnumber, "AS"), "as")
				if n, err := strconv.Atoi(num); err == nil {
					if label, ok := asnLabels[n]; ok {
						return label
					}
				}
			}
			if ip := ntHopIP(h.Address); ip != "" {
				if label := classifyIP(ip); label != "" {
					return label
				}
			}
		}
	}
	return "未知"
}

// 用 nexttrace 测到目标的线路(-M 关掉 maptrace, 否则其 API 失败会吞掉 JSON 输出)。
// nexttrace 不可用、运行失败或解析失败时返回 nil, 由调用方回落到系统 traceroute。
func routeViaNexttrace(target string) *string {
	if _, err := exec.LookPath("nexttrace"); err != nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	out, errOut, err := runCmdSplit(ctx, "nexttrace", "--json", "-q", "1", "-m", "20", "-M", target)
	if err != nil {
		logf("nexttrace 失败(%s): %s", target, firstLine(errOut))
		return nil
	}
	var res ntResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		logf("nexttrace 输出解析失败(%s): %v", target, err)
		return nil
	}
	label := classifyNtHops(res.Hops)
	return &label
}

// routesDue 本轮是否该重测线路(首次或已到预约时间)。
func (c *collector) routesDue(now time.Time) bool {
	return c.lastRoute == nil || !now.Before(c.nextRoute)
}

// scheduleNextRoute 预约下次线路探测(间隔 + 0-30 秒抖动, 避免多节点同步探测)。
func (c *collector) scheduleNextRoute(now time.Time) {
	c.nextRoute = now.Add(c.routeInterval + time.Duration(mathrand.Int63n(30))*time.Second)
}

// ---------- 采集入口 ----------

func (c *collector) collect(node string) report {
	hn, _ := os.Hostname()
	now := time.Now()
	cpu := c.cpuUsage()
	cur := readNet()
	var rxRate, txRate uint64
	if !c.prevNetAt.IsZero() {
		secs := now.Sub(c.prevNetAt).Seconds()
		if secs > 0 {
			if cur.rx >= c.prevNet.rx {
				rxRate = uint64(float64(cur.rx-c.prevNet.rx) / secs)
			}
			if cur.tx >= c.prevNet.tx {
				txRate = uint64(float64(cur.tx-c.prevNet.tx) / secs)
			}
		}
	}
	// 累计流量: 本轮增量进 state; 重启后 /proc 计数归零, 直接加当前值。
	if c.haveState {
		if cur.rx >= c.lastRx {
			c.cumRx += cur.rx - c.lastRx
		} else {
			c.cumRx += cur.rx
		}
		if cur.tx >= c.lastTx {
			c.cumTx += cur.tx - c.lastTx
		} else {
			c.cumTx += cur.tx
		}
	} else {
		c.cumRx = cur.rx
		c.cumTx = cur.tx
		c.haveState = true
	}
	c.lastRx, c.lastTx = cur.rx, cur.tx
	c.prevNet, c.prevNetAt = cur, now
	c.saveState()

	memTotal, memUsed := readMem()
	diskTotal, diskUsed := readDisk()

	ping := map[string]*pingResult{}
	route := map[string]map[string]*string{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for k, targets := range pingTargets {
		wg.Add(1)
		go func(k string, targets []string) {
			defer wg.Done()
			p, _ := pingWithFallback(targets)
			mu.Lock()
			ping[k] = p
			mu.Unlock()
		}(k, targets)
	}
	// 线路探测降频: 指标每轮都采, 线路(nexttrace/traceroute)默认每 5 分钟才重测一次,
	// 期间用上次的结果, 避免高频探测被运营商/防火墙风控。
	probeRoutes := c.routesDue(now)
	if probeRoutes {
		// 去程线路: 每运营商 3 个城市各测一次, 并发执行;
		// 优先 nexttrace(逐跳 ASN), 不可用或失败时回落系统 traceroute+网段表
		for k, cities := range routeTargets {
			for city, target := range cities {
				wg.Add(1)
				go func(k, city, target string) {
					defer wg.Done()
					rt := routeViaNexttrace(target)
					if rt == nil {
						rt = tracerouteOne(target)
					}
					mu.Lock()
					if route[k] == nil {
						route[k] = map[string]*string{}
					}
					route[k][city] = rt
					mu.Unlock()
				}(k, city, target)
			}
		}
	}
	wg.Wait()
	if probeRoutes {
		// 缓存线路结果, 预约下次探测(加 0-30 秒抖动, 避免多节点同步探测)
		c.lastRoute = route
		c.scheduleNextRoute(time.Now())
	} else {
		route = c.lastRoute
	}

	// 回程探测: 从本机(国内) traceroute 到目标 VPS, 分类后随本轮上报。
	// 只有成功分类的才上报, 测不出(未知)不覆盖上一次的好结果。
	// 与去程线路共用降频: 测出后缓存, 未到下次探测时间直接用缓存。
	var ret map[string]string
	if c.carrier != "" && len(c.returnTargets) > 0 {
		if probeRoutes {
			ret = map[string]string{}
			var rwg sync.WaitGroup
			var rmu sync.Mutex
			for _, t := range c.returnTargets {
				rwg.Add(1)
				go func(t returnTarget) {
					defer rwg.Done()
					if label := tracerouteOne(t.ip); label != nil && *label != "未知" {
						rmu.Lock()
						ret[t.node] = *label
						rmu.Unlock()
					}
				}(t)
			}
			rwg.Wait()
			if c.lastRet == nil {
				c.lastRet = map[string]string{}
			}
			for k, v := range ret {
				c.lastRet[k] = v
			}
			ret = c.lastRet
		} else {
			ret = c.lastRet
		}
	}

	r := report{
		Node: node, Name: c.name, Carrier: c.carrier, ReturnRoutes: ret, TS: now.Unix(), Hostname: hn,
		Uptime: readUptime(), CPU: cpu, Load: readLoad(),
		MemTotal: memTotal, MemUsed: memUsed,
		DiskTotal: diskTotal, DiskUsed: diskUsed,
		NetRx: c.cumRx, NetTx: c.cumTx,
		NetRxRate: rxRate, NetTxRate: txRate,
		Ping: ping, Route: route,
	}
	return r
}

// ---------- 上报 ----------

func push(cfg config, r report) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(body) > 65536 {
		return fmt.Errorf("report too large")
	}
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(5 * time.Second)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
		if err != nil {
			cancel()
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
		req.Header.Set("User-Agent", "vps-probe-agent/1.0")
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		cancel()
		if resp.StatusCode == http.StatusOK {
			return nil
		}
		lastErr = fmt.Errorf("worker 返回 HTTP %d", resp.StatusCode)
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusBadRequest {
			return lastErr // 鉴权/格式问题重试也没用
		}
	}
	return lastErr
}

func round1(f float64) float64 {
	return math.Round(f*10) / 10
}

func logf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[%s] ", time.Now().Format("15:04:05"))
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

// 未指定节点 id 时按主机名自动生成: 小写、非法字符变连字符、去重/去首尾连字符、最长 32 位;
// 主机名无效时用 node- + 6 位随机 hex。
func deriveNodeID() string {
	hn, _ := os.Hostname()
	s := strings.ToLower(hn)
	var b strings.Builder
	lastDash := true
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
		} else if !lastDash {
			b.WriteRune('-')
			lastDash = true
		}
	}
	id := strings.Trim(b.String(), "-")
	if len(id) > 32 {
		id = strings.Trim(id[:32], "-")
	}
	if id == "" {
		var rb [3]byte
		if _, err := rand.Read(rb[:]); err != nil {
			n := time.Now().UnixNano()
			rb = [3]byte{byte(n), byte(n >> 8), byte(n >> 16)}
		}
		id = fmt.Sprintf("node-%x", rb)
	}
	return id
}

func main() {
	cfg := loadConfig()
	if cfg.Node == "" {
		cfg.Node = deriveNodeID()
		logf("未指定节点 id, 已按主机名自动生成: %s", cfg.Node)
	}
	if _, err := exec.LookPath("nexttrace"); err == nil {
		logf("线路检测: nexttrace (逐跳 ASN)")
	} else {
		logf("线路检测: traceroute + 网段表 (未装 nexttrace)")
	}
	for k, env := range map[string]string{"ct": "PROBE_PING_CT", "cu": "PROBE_PING_CU", "cm": "PROBE_PING_CM"} {
		if v := os.Getenv(env); v != "" {
			pingTargets[k] = []string{v}
		}
	}
	if cfg.Carrier != "" && cfg.Carrier != "ct" && cfg.Carrier != "cu" && cfg.Carrier != "cm" {
		fmt.Fprintln(os.Stderr, "carrier 只允许 ct/cu/cm")
		os.Exit(2)
	}
	var rts []returnTarget
	if cfg.ReturnTargets != "" {
		for _, part := range strings.Split(cfg.ReturnTargets, ",") {
			kv := strings.SplitN(strings.TrimSpace(part), ":", 2)
			if len(kv) != 2 || net.ParseIP(kv[1]) == nil {
				fmt.Fprintf(os.Stderr, "回程目标格式错误: %s (应为 节点id:IP, 如 la:1.2.3.4)\n", part)
				os.Exit(2)
			}
			if ok, _ := regexp.MatchString(`^[a-z0-9][a-z0-9-]{0,31}$`, kv[0]); !ok {
				fmt.Fprintln(os.Stderr, "回程目标节点 id 非法: "+kv[0])
				os.Exit(2)
			}
			rts = append(rts, returnTarget{node: kv[0], ip: kv[1]})
		}
	}

	c := &collector{name: cfg.Name, carrier: cfg.Carrier, returnTargets: rts, routeInterval: cfg.RouteInterval}
	if cfg.StateDir != "" {
		c.statePath = filepath.Join(cfg.StateDir, "state.json")
		c.loadState()
	}

	if cfg.Once {
		r := c.collect(cfg.Node)
		b, _ := json.MarshalIndent(r, "", "  ")
		fmt.Println(string(b))
		return
	}

	if cfg.URL == "" || cfg.Token == "" {
		fmt.Fprintln(os.Stderr, "缺少必要参数: -url、-token (或环境变量 PROBE_URL/PROBE_TOKEN)")
		os.Exit(2)
	}
	if !cfg.AllowHTTP && !strings.HasPrefix(cfg.URL, "https://") {
		fmt.Fprintln(os.Stderr, "上报地址必须是 https (本地测试加 -allow-http)")
		os.Exit(2)
	}
	if ok, _ := regexp.MatchString(`^[a-z0-9][a-z0-9-]{0,31}$`, cfg.Node); !ok {
		fmt.Fprintln(os.Stderr, "节点 id 只允许小写字母、数字、连字符, 1-32 位")
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logf("agent 启动: 节点 %s, 间隔 %s", cfg.Node, cfg.Interval)
	for {
		r := c.collect(cfg.Node)
		if err := push(cfg, r); err != nil {
			logf("上报失败: %v", err)
		} else {
			logf("上报成功: cpu %.1f%% mem %.1f%%", r.CPU, 100*float64(r.MemUsed)/float64(maxU64(r.MemTotal, 1)))
		}
		select {
		case <-ctx.Done():
			logf("收到退出信号, 停止")
			return
		case <-time.After(cfg.Interval):
		}
	}
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
