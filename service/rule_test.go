package service

import (
	"encoding/json"
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/model"
	"github.com/tidwall/gjson"
	"regexp"
	"testing"
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

func TestRuleServiceBlackList(t *testing.T) {
	content := `{
    "status": "success",
    "code": 200,
    "data": {
        "mode": "reject",
        "rules": [
            {
                "id": 2,
                "type": "reg",
                "pattern": "(Subject|HELO|SMTP)"
            },
            {
                "id": 3,
                "type": "domain",
                "pattern": "baidu.com"
            },
            {
                "id": 4,
                "type": "reg",
                "pattern": "(api|ps|sv|offnavi|newvector|ulog\\.imap|newloc)(\\.map|)\\.(baidu|n\\.shifen)\\.com"
            },
            {
                "id": 5,
                "type": "reg",
                "pattern": "(.*\\.||)(dafahao|minghui|dongtaiwang|epochtimes|ntdtv|falundafa|wujieliulan|zhengjian)\\.(org|com|net)"
            },
            {
                "id": 7,
                "type": "ip",
                "pattern": "192.168.1.1"
            }
        ]
    },
    "message": "获取节点审计规则成功"
}`

	rule := new(model.Rule)
	err := json.Unmarshal([]byte(gjson.Get(content, "data").String()), rule)
	if err != nil {
		t.Fatal(err)
	}
	GetRuleService().Load(rule)
	if _, ok, _ := GetRuleService().judgeWithCache("ntdtv.com",0); ok {
		t.Fatal("ntd.tv test fail")
	}

	if _, ok, _ := GetRuleService().judgeWithCache("baidu.com",0); ok {
		t.Fatal("baidu.com test fail")
	}

	if _, ok, _ := GetRuleService().judgeWithCache("192.168.1.1",0); !ok {
		t.Fatal("192.168.1.1 test fail")
	}
}

func TestRuleServiceWhiteList(t *testing.T) {
	content := `{
    "status": "success",
    "code": 200,
    "data": {
        "mode": "allow",
        "rules": [
            {
                "id": 2,
                "type": "reg",
                "pattern": "(Subject|HELO|SMTP)"
            },
            {
                "id": 3,
                "type": "domain",
                "pattern": "baidu.com"
            },
            {
                "id": 4,
                "type": "reg",
                "pattern": "(api|ps|sv|offnavi|newvector|ulog\\.imap|newloc)(\\.map|)\\.(baidu|n\\.shifen)\\.com"
            },
            {
                "id": 5,
                "type": "reg",
                "pattern": "(.*\\.||)(dafahao|minghui|dongtaiwang|epochtimes|ntdtv|falundafa|wujieliulan|zhengjian)\\.(org|com|net)"
            },
            {
                "id": 7,
                "type": "ip",
                "pattern": "192.168.1.1"
            }
        ]
    },
    "message": "获取节点审计规则成功"
}`

	rule := new(model.Rule)
	err := json.Unmarshal([]byte(gjson.Get(content, "data").String()), rule)
	if err != nil {
		t.Fatal(err)
	}
	GetRuleService().Load(rule)
	if _, ok, _ := GetRuleService().judgeWithCache("ntdtv.com",0); !ok {
		t.Fatal("ntd.tv test fail")
	}

	if _, ok, _ := GetRuleService().judgeWithCache("baidu.com",0); !ok {
		t.Fatal("baidu.com test fail")
	}

	if _, ok, _ := GetRuleService().judgeWithCache("192.168.1.1",0); !ok {
		t.Fatal("192.168.1.1 test fail")
	}

	if _, ok, _ := GetRuleService().judgeWithCache("google.com",0); ok {
		t.Fatal("google.com test fail")
	}
}

func TestJudgeCache(t *testing.T){
	content := `{
    "status": "success",
    "code": 200,
    "data": {
        "mode": "allow",
        "rules": [
            {
                "id": 2,
                "type": "reg",
                "pattern": "(Subject|HELO|SMTP)"
            },
            {
                "id": 3,
                "type": "domain",
                "pattern": "baidu.com"
            },
            {
                "id": 4,
                "type": "reg",
                "pattern": "(api|ps|sv|offnavi|newvector|ulog\\.imap|newloc)(\\.map|)\\.(baidu|n\\.shifen)\\.com"
            },
            {
                "id": 5,
                "type": "reg",
                "pattern": "(.*\\.||)(dafahao|minghui|dongtaiwang|epochtimes|ntdtv|falundafa|wujieliulan|zhengjian)\\.(org|com|net)"
            },
            {
                "id": 7,
                "type": "ip",
                "pattern": "192.168.1.1"
            }
        ]
    },
    "message": "获取节点审计规则成功"
}`

	rule := new(model.Rule)
	err := json.Unmarshal([]byte(gjson.Get(content, "data").String()), rule)
	if err != nil {
		t.Fatal(err)
	}
	GetRuleService().Load(rule)

	_, ok, isCache := GetRuleService().judgeWithCache("ntdtv.com",0)
	if !ok && !isCache {
		t.Fatal("ntd.tv cache test fail")
	}

	_, ok, isCache = GetRuleService().judgeWithCache("ntdtv.com",0)
	if !ok && isCache {
		t.Fatal("ntd.tv  cache test fail")
	}

	_, ok, isCache = GetRuleService().judgeWithCache("ntdtv.com",1)
	if !ok && !isCache {
		t.Fatal("ntd.tv  cache test fail")
	}
}
