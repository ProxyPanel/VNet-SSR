package model

import (
	"encoding/json"
	"fmt"
	"github.com/tidwall/gjson"
	"testing"
)

func TestRuleConvert(t *testing.T){
	res := `{
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
                "type": "reg",
                "pattern": "BitTorrent protocol"
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
                "type": "reg",
                "pattern": "(^.*\\@)(guerrillamail|guerrillamailblock|sharklasers|grr|pokemail|spam4|bccto|chacuo|027168)\\.(info|biz|com|de|net|org|me|la)"
            }
        ]
    },
    "message": "获取节点审计规则成功"
}`
	rule := Rule{}
	err := json.Unmarshal([]byte(gjson.Get(res,"data").String()),&rule)
	if err != nil{
		t.Fatal(err)
	}
	fmt.Printf("%+v\n",rule)
}
