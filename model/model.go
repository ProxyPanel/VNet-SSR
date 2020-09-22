package model

type NodeInfo struct {
	ID            int    `json:"id"`
	Port          string `json:"port"`
	Passwd        string `json:"passwd"`
	Method        string `json:"method"`
	Protocol      string `json:"protocol"`
	Obfs          string `json:"obfs"`
	ProtocolParam string `json:"protocol_param"`
	ObfsParam     string `json:"obfs_param"`
	PushPort      int    `json:"push_port"`
	Single        int    `json:"single"`
	Secret        string `json:"secret"`
	SpeedLimit    uint64 `json:"speed_limit"`
	IsUDP         int    `json:"is_udp"`
	ClientLimit   int    `json:"client_limit"`
}

type UserInfo struct {
	Uid    int    `json:"uid"`
	Port   int    `json:"port"`
	Passwd string `json:"passwd"`
	Limit  uint64 `json:"speed_limit"`
	Enable int    `json:"enable"`
}

type UserTraffic struct {
	Uid       int   `json:"uid"`
	Upload    int64 `json:"upload"'`
	Download  int64 `json:"download"`
	UpSpeed   int64 `json:"upspeed"`
	DownSpeed int64 `json:"downspeed"`
}

type NodeOnline struct {
	Uid int    `json:"uid"`
	IP  string `json:"ip"`
}

type NodeStatus struct {
	CPU    string `json:"cpu"`
	MEM    string `json:"mem"`
	NET    string `json:"net"`
	DISK   string `json:"disk"`
	UPTIME int    `json:"uptime"`
}

type Rule struct {
	Model string     `json:"mode"`
	Rules []RuleItem `json:"rules"`
}

type RuleItem struct {
	Id      int    `json:"id"`
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
}

type Trigger struct {
	Uid    int    `json:"uid"`
	RuleId int    `json:"rule_id"`
	Reason string `json:"reason"`
}
