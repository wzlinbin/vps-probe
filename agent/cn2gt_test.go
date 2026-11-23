package main

import (
	"encoding/json"
	"testing"
)

// 用户那条 nexttrace 路由(回程 VPS -> 杭州电信):
// hop3 218.30.48.73 AS4134, hop4-7 59.43.x.x(无 ASN), hop8 110.94.1.50 AS4134, hop9 AS58461
var userTrace = `{"Hops":[[],[],[{"Success":true,"Address":"218.30.48.73","Geo":{"asnumber":"AS4134"}}],[{"Success":true,"Address":"59.43.189.37","Geo":null}],[{"Success":true,"Address":"59.43.39.169","Geo":null}],[{"Success":true,"Address":"59.43.159.97","Geo":null}],[{"Success":true,"Address":"59.43.80.145","Geo":null}],[{"Success":true,"Address":"110.94.1.50","Geo":{"asnumber":"AS4134"}}],[{"Success":true,"Address":"220.191.200.18","Geo":{"asnumber":"AS58461"}}]]}`

// 纯 CN2 GIA: 直接进 59.43, 无 163 在前
var giaTrace = `{"Hops":[[],[],[{"Success":true,"Address":"59.43.1.1","Geo":null}],[{"Success":true,"Address":"59.43.2.2","Geo":null}],[{"Success":true,"Address":"220.191.200.18","Geo":{"asnumber":"AS58461"}}]]}`

// 纯 163: 只有 202.97/AS4134, 无 59.43
var pure163Trace = `{"Hops":[[],[],[{"Success":true,"Address":"202.97.1.1","Geo":{"asnumber":"AS4134"}}],[{"Success":true,"Address":"202.97.2.2","Geo":null}]]}`

func TestClassifyNtHopsCN2GT(t *testing.T) {
	cases := []struct{ name, js, want string }{
		{"用户路由应为 CN2 GT", userTrace, "CN2 GT"},
		{"纯 CN2 GIA", giaTrace, "CN2"},
		{"纯 163", pure163Trace, "163"},
	}
	for _, c := range cases {
		var res ntResult
		if err := json.Unmarshal([]byte(c.js), &res); err != nil {
			t.Fatalf("%s: 解析失败: %v", c.name, err)
		}
		if got := classifyNtHops(res.Hops); got != c.want {
			t.Errorf("%s: 得到 %q, 想要 %q", c.name, got, c.want)
		}
	}
}

func TestRouteSegmentsUserTrace(t *testing.T) {
	var res ntResult
	if err := json.Unmarshal([]byte(userTrace), &res); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	label, exit, border, domestic := analyzeNtHops(res.Hops)
	if label != "CN2 GT" {
		t.Errorf("标签应为 CN2 GT, 得到 %q", label)
	}
	if exit != "218.30.48.73 (AS4134)" {
		t.Errorf("出口节点应为 218.30.48.73 (AS4134), 得到 %q", exit)
	}
	if border != "163 → CN2" {
		t.Errorf("跨境段应为 163 → CN2, 得到 %q", border)
	}
	if domestic != "CN2" {
		t.Errorf("国内骨干段应为 CN2, 得到 %q", domestic)
	}
	// 纯 CN2 GIA: 出口即 CN2, 跨境与国内均为 CN2
	var gia ntResult
	if err := json.Unmarshal([]byte(giaTrace), &gia); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	label, exit, border, domestic = analyzeNtHops(gia.Hops)
	if label != "CN2" || border != "CN2" || domestic != "CN2" {
		t.Errorf("纯 GIA 应为 CN2/CN2/CN2, 得到 %q/%q/%q", label, border, domestic)
	}
	if exit != "59.43.1.1" {
		t.Errorf("纯 GIA 出口应为 59.43.1.1, 得到 %q", exit)
	}
}
