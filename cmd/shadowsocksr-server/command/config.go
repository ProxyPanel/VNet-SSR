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
	Example  string
	Type     reflect.Kind
	Required bool
}

var flagConfigs = []FlagSetting{
	FlagSetting{
		Type:     reflect.String,
		Name:     API_HOST,
		Usage:    "api host example: http://localhost",
		Required: true,
	},
	FlagSetting{
		Type:     reflect.String,
		Name:     HOST,
		Usage:    "host example: 0.0.0.0",
		Required: true,
		Default:  "0.0.0.0",
	},
	FlagSetting{
		Type:     reflect.Int,
		Name:     NODE_ID,
		Usage:    "node_id",
		Required: true,
	},
	FlagSetting{
		Type:     reflect.String,
		Name:     KEY,
		Usage:    "key",
		Required: true,
	},
}
