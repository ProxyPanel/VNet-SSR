package service

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/model"
)

func BenchmarkTest(t *testing.B) {
	regs := make([]*regexp.Regexp, 0, 10000)
	for i := 0; i < 10000; i++ {
		reg, _ := regexp.Compile(fmt.Sprintf("www.test%d.com", i))
		regs = append(regs, reg)
	}
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		index := t.N % 2048
		test := fmt.Sprintf("asdasdasdadasdaswww.test%d.com", index)
		for _, item := range regs {
			item.Match([]byte(test))
		}
	}
}

const rejectRuleJSON = `{
    "mode": "reject",
    "rules": [
        {"id": 2, "type": "reg", "pattern": "(Subject|HELO|SMTP)"},
        {"id": 3, "type": "domain", "pattern": "baidu.com"},
        {"id": 5, "type": "reg", "pattern": "(.*\\.||)(dafahao|minghui|dongtaiwang|epochtimes|ntdtv|falundafa|wujieliulan|zhengjian)\\.(org|com|net)"},
        {"id": 7, "type": "ip", "pattern": "192.168.1.1"}
    ]
}`

const allowRuleJSON = `{
    "mode": "allow",
    "rules": [
        {"id": 2, "type": "reg", "pattern": "(Subject|HELO|SMTP)"},
        {"id": 3, "type": "domain", "pattern": "baidu.com"},
        {"id": 5, "type": "reg", "pattern": "(.*\\.||)(dafahao|minghui|dongtaiwang|epochtimes|ntdtv|falundafa|wujieliulan|zhengjian)\\.(org|com|net)"},
        {"id": 7, "type": "ip", "pattern": "192.168.1.1"}
    ]
}`

func loadRule(t *testing.T, data string) {
	t.Helper()
	rule := new(model.Rule)
	if err := json.Unmarshal([]byte(data), rule); err != nil {
		t.Fatal(err)
	}
	GetRuleService().Load(rule)
}

func TestRuleServiceBlackList(t *testing.T) {
	loadRule(t, rejectRuleJSON)
	if _, ok := GetRuleService().judgeCached("ntdtv.com"); ok {
		t.Fatal("ntdtv.com test fail")
	}
	if _, ok := GetRuleService().judgeCached("baidu.com"); ok {
		t.Fatal("baidu.com test fail")
	}
	if _, ok := GetRuleService().judgeCached("192.168.1.1"); ok {
		t.Fatal("192.168.1.1 test fail")
	}
}

func TestRuleServiceWhiteList(t *testing.T) {
	loadRule(t, allowRuleJSON)
	if _, ok := GetRuleService().judgeCached("ntdtv.com"); !ok {
		t.Fatal("ntdtv.com test fail")
	}
	if _, ok := GetRuleService().judgeCached("baidu.com"); !ok {
		t.Fatal("baidu.com test fail")
	}
	if _, ok := GetRuleService().judgeCached("google.com"); ok {
		t.Fatal("google.com test fail")
	}
}

func TestRuleServiceDomainWildcardAndCidr(t *testing.T) {
	rule := &model.Rule{
		Model: RuleModeReject,
		Rules: []model.RuleItem{
			{Id: 1, Type: RuleTypeDomain, Pattern: "*.example.com"},
			{Id: 2, Type: RuleTypeIp, Pattern: "10.0.0.0/8"},
			{Id: 3, Type: RuleTypeDomain, Pattern: "exact.test"},
			{Id: 4, Type: RuleTypeIp, Pattern: "192.168.1.1"},
		},
	}
	GetRuleService().Load(rule)

	cases := []struct {
		host  string
		allow bool
	}{
		{"example.com", false},
		{"www.example.com", false},
		{"sub.a.example.com", false},
		{"EXAMPLE.COM", false},
		{"notexample.com", true},
		{"10.1.2.3", false},
		{"11.1.2.3", true},
		{"exact.test", false},
		{"a.exact.test", true},
		{"192.168.1.1", false},
		{"192.168.1.2", true},
	}
	for _, c := range cases {
		if _, ok := GetRuleService().judgeCached(c.host); ok != c.allow {
			t.Fatalf("%s: got allow=%v want %v", c.host, !ok, c.allow)
		}
	}
}

// 判定缓存按 host 共享、上报去重按 (host,identity) 分账：同一被拒域名的每个账号都要各自留下触发记录
func TestReportDedupPerIdentity(t *testing.T) {
	loadRule(t, rejectRuleJSON)

	if !GetRuleService().shouldReport("baidu.com", 1) {
		t.Fatal("账号 1 第一次命中该上报")
	}
	if GetRuleService().shouldReport("baidu.com", 1) {
		t.Fatal("同一 (host,账号) 窗口内不该重复上报")
	}
	if !GetRuleService().shouldReport("baidu.com", 2) {
		t.Fatal("同一 host 的另一个账号必须能上报，否则缓存吞掉了触发记录")
	}
}

// 规则换入后判定与上报去重都作废：旧窗口不该抑制新规则下的上报
func TestLoadInvalidatesCaches(t *testing.T) {
	loadRule(t, rejectRuleJSON)
	GetRuleService().shouldReport("baidu.com", 1)
	GetRuleService().judgeCached("baidu.com")

	loadRule(t, allowRuleJSON)
	if _, ok := GetRuleService().judgeCached("baidu.com"); !ok {
		t.Fatal("新规则判定没生效")
	}
	if !GetRuleService().shouldReport("baidu.com", 1) {
		t.Fatal("换规则后上报去重要重置")
	}
}

// 反查不到账号的触发不入队（面板 exists:user 必拒，入队等于往重投队列里塞毒丸）
func TestUnknownIdentityTriggerIsDropped(t *testing.T) {
	loadRule(t, rejectRuleJSON)

	if GetRuleService().JudgeHostWithReport("baidu.com", 99999999, core.AuditContext{Target: "1.2.3.4:80"}) {
		t.Fatal("命中 reject 应返回 false")
	}
	GetRuleService().triggers.drain()
	GetRuleService().triggers.mu.Lock()
	n := len(GetRuleService().triggers.pending)
	GetRuleService().triggers.mu.Unlock()
	if n != 0 {
		t.Fatalf("uid 反查不到的触发不该入队, 队列 %d 条", n)
	}
}

// 入队的现场字段按面板 max 截断，超长不会整条被拒
func TestTriggerFieldsTruncated(t *testing.T) {
	loadRule(t, rejectRuleJSON)
	s := GetSSRManager()
	s.userTableLock.Lock()
	s.userTable[7] = &model.UserInfo{Uid: 7, Port: 30007, Passwd: "p", Enable: 1}
	s.identityIndex[30007] = 7
	s.userTableLock.Unlock()

	long := strings.Repeat("a", 3000)
	GetRuleService().JudgeHostWithReport("baidu.com", 30007, core.AuditContext{Target: "h.example:" + long, SniffProtocol: "http", SniffHost: "baidu.com", SniffUri: long})

	GetRuleService().triggers.mu.Lock()
	defer GetRuleService().triggers.mu.Unlock()
	if len(GetRuleService().triggers.pending) != 1 {
		t.Fatalf("合法触发应恰好入队一条: %d", len(GetRuleService().triggers.pending))
	}
	tr := GetRuleService().triggers.pending[0]
	if len(tr.Target) > 255 || len(tr.SniffUri) > 1024 {
		t.Fatalf("现场字段未按面板上限截断: target=%d uri=%d", len(tr.Target), len(tr.SniffUri))
	}
}

func TestCutBytesKeepsUTF8(t *testing.T) {
	s := "中文abc中文abc"
	cut := cutBytes(s, 7) // 7 字节：中文(3)+中文(3) 后只能放下 'a'
	if len(cut) > 7 || !utf8.ValidString(cut) {
		t.Fatalf("截断越界或切断多字节: %q", cut)
	}
	if cutBytes("short", 255) != "short" {
		t.Fatal("未超限不该改动")
	}
}
