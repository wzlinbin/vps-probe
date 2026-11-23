package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// 样本 nexttrace --json 输出(结构按 NTrace-core v1.7.6 源码核对:
// Result.Hops [][]Hop, Hop.Geo.asnumber 如 "AS4134", Hop.Address 为字符串 IP 或 null)。
func TestClassifyNtHops(t *testing.T) {
	cases := []struct {
		name string
		json string
		want string
	}{
		{
			"电信 163 (ASN)",
			`{"Hops": [[{"Success": true, "Address": "202.97.1.1", "Geo": {"asnumber": "AS4134"}}]]}`,
			"163",
		},
		{
			"电信 CN2 (ASN)",
			`{"Hops": [[{"Success": true, "Address": "59.43.1.1", "Geo": {"asnumber": "AS4809"}}]]}`,
			"CN2",
		},
		{
			"联通 9929 (ASN)",
			`{"Hops": [[{"Success": true, "Address": "219.158.1.1", "Geo": {"asnumber": "AS9929"}}]]}`,
			"9929",
		},
		{
			"联通 4837 (ASN)",
			`{"Hops": [[{"Success": true, "Address": "218.105.1.1", "Geo": {"asnumber": "AS4837"}}]]}`,
			"4837",
		},
		{
			"移动 CMIN2 (ASN)",
			`{"Hops": [[{"Success": true, "Address": "223.96.1.1", "Geo": {"asnumber": "AS58807"}}]]}`,
			"CMIN2",
		},
		{
			"移动普通 9808 (ASN)",
			`{"Hops": [[{"Success": true, "Address": "221.179.1.1", "Geo": {"asnumber": "AS9808"}}]]}`,
			"9808",
		},
		{
			"移动地方网 AS56048 也算普通移动",
			`{"Hops": [[{"Success": true, "Address": "221.179.1.1", "Geo": {"asnumber": "AS56048"}}]]}`,
			"9808",
		},
		{
			"无 ASN 时用跳点 IP 走网段表",
			`{"Hops": [[{"Success": true, "Address": "202.97.1.1", "Geo": null}]]}`,
			"163",
		},
		{
			"先取第一个能判出的跳点(跳过无归属的)",
			`{"Hops": [[{"Success": true, "Address": "8.8.8.8", "Geo": {"asnumber": "AS15169"}}], [{"Success": true, "Address": "59.43.1.1", "Geo": {"asnumber": "AS4809"}}]]}`,
			"CN2",
		},
		{
			"失败跳点跳过(null Address)",
			`{"Hops": [[{"Success": false, "Address": null, "Geo": null}], [{"Success": true, "Address": "219.158.1.1", "Geo": {"asnumber": "AS9929"}}]]}`,
			"9929",
		},
		{
			"都判不出返回未知",
			`{"Hops": [[{"Success": true, "Address": "8.8.8.8", "Geo": {"asnumber": "AS15169"}}]]}`,
			"未知",
		},
		{
			"空 hops 返回未知",
			`{"Hops": []}`,
			"未知",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var res ntResult
			if err := json.Unmarshal([]byte(c.json), &res); err != nil {
				t.Fatalf("样本 JSON 解析失败: %v", err)
			}
			if got := classifyNtHops(res.Hops); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestNtHopIP(t *testing.T) {
	if got := ntHopIP(json.RawMessage(`"1.2.3.4"`)); got != "1.2.3.4" {
		t.Fatalf("字符串 IP: got %q", got)
	}
	if got := ntHopIP(json.RawMessage(`null`)); got != "" {
		t.Fatalf("null: got %q", got)
	}
	if got := ntHopIP(nil); got != "" {
		t.Fatalf("空: got %q", got)
	}
}

func TestTCPPing(t *testing.T) {
	// 本地监听端口: 建连成功(SYN-ACK)应返回延迟
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	if rtt, ok := tcpPingOne("127.0.0.1", port); !ok || rtt <= 0 {
		t.Fatalf("本地监听端口应建连成功, ok=%v rtt=%v", ok, rtt)
	}
	// 已关闭的端口: RST 也算收到回包, 应返回延迟
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	_, closedPort, _ := net.SplitHostPort(ln2.Addr().String())
	ln2.Close()
	if rtt, ok := tcpPingOne("127.0.0.1", closedPort); !ok || rtt <= 0 {
		t.Fatalf("已关闭端口(RST)应算收到回包, ok=%v rtt=%v", ok, rtt)
	}
	// 不可达 IP: 3 次全丢, Avg=nil、Loss=100
	r := tcpPingTarget("10.255.255.1")
	if r.Avg != nil {
		t.Fatalf("不可达 IP 的 Avg 应为 nil, got %v", *r.Avg)
	}
	if r.Loss == nil || *r.Loss != 100 {
		t.Fatalf("不可达 IP 的 Loss 应为 100, got %v", r.Loss)
	}
}

func TestRoutesDue(t *testing.T) {
	c := &collector{routeInterval: 5 * time.Minute}
	now := time.Now()
	if !c.routesDue(now) {
		t.Fatal("首次应探测")
	}
	c.lastRoute = map[string]map[string]*string{"ct": {"sh": strPtr("163")}}
	c.scheduleNextRoute(now)
	if c.routesDue(now) {
		t.Fatal("刚预约后不应立即再探")
	}
	if c.nextRoute.Before(now.Add(5*time.Minute)) || c.nextRoute.After(now.Add(5*time.Minute+30*time.Second)) {
		t.Fatalf("下次探测时间应在 5 分~5 分 30 秒之间, got %v", c.nextRoute.Sub(now))
	}
	if !c.routesDue(now.Add(6 * time.Minute)) {
		t.Fatal("超过间隔后应探测")
	}
}

func strPtr(s string) *string { return &s }
