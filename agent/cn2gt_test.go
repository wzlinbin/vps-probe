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
