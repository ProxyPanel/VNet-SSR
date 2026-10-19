package command

import "reflect"

const (
	API_HOST   = "api_host"
	HOST       = "host"
	NODE_ID    = "node_id"
	KEY        = "key"
)

type FlagSetting struct {
	Name     string
	Default  interface{}
	Usage    string
	Type     reflect.Kind
	Required bool
}

var flagConfigs = []FlagSetting{
	FlagSetting{
		Type:     reflect.String,
		Name:     API_HOST,
		Usage:    "面板基址，不带路径，例 https://panel.example.com",
		Required: true,
	},
	FlagSetting{
		Type:     reflect.String,
		Name:     HOST,
		Usage:    "监听地址；双栈写 [::]",
		Required: true,
		Default:  "0.0.0.0",
	},
	FlagSetting{
		Type:     reflect.Int,
		Name:     NODE_ID,
		Usage:    "面板上的节点 id，填 0 视为未填",
		Required: true,
	},
	FlagSetting{
		Type:     reflect.String,
		Name:     KEY,
		Usage:    "节点授权 key（面板的 node_auth.key）",
		Required: true,
	},
}
