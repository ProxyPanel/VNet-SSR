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
	RedirectUrl   string `json:"redirect_url"`
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
	Upload    int64 `json:"upload"`
	Download  int64 `json:"download"`
	UpSpeed   int64 `json:"upspeed"`
	DownSpeed int64 `json:"downspeed"`
	// ReportID 同一批增量的所有行共用，重发时不变：面板按 (node_id, report_id, uid) 去重，
	// 否则「面板已入账但响应丢失」的那一批会被再累加一次
	ReportID string `json:"report_id"`
}

type NodeOnline struct {
	Uid int    `json:"uid"`
	IP  string `json:"ip"`
	// ReportID 同一批在线记录共用，重发时不变：面板按 (node_id, report_id) 认领去重，
	// 否则「面板已入账但响应丢失」的那一批会被再插一遍在线行
	ReportID string `json:"report_id"`
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

// Trigger 是一次审计命中的完整现场：reason 为被命中的判定对象，
// target 是连接真实去向，sniff_* 是首包嗅出的身份（HTTP Host/URL 或 TLS SNI），未嗅到则为空
type Trigger struct {
	Uid           int    `json:"uid"`
	RuleId        int    `json:"rule_id"`
	Reason        string `json:"reason"`
	Target        string `json:"target,omitempty"`
	SniffProtocol string `json:"sniff_protocol,omitempty"`
	SniffHost     string `json:"sniff_host,omitempty"`
	SniffUri      string `json:"sniff_uri,omitempty"`
}
