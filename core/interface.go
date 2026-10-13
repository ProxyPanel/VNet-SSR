package core

type Closeable interface {
	Close() error;
}

type Runable interface {
	Start() error;
}

type Reloadable interface {
	Reload() error;
}

// AuditContext 是判定发生时的连接现场，随命中一起进 trigger 上报
type AuditContext struct {
	Target        string // 连接真实去向 host:port
	SniffProtocol string // 首包嗅探结果：http/tls，未嗅到为空
	SniffHost     string // HTTP Host 头或 TLS SNI
	SniffUri      string // HTTP 请求路径（含 query）
}

type HostFirewall interface {
	JudgeHostWithReport(ipOrDomain string, identity int, ev AuditContext) bool
}

type ObfsProtocolService interface {
	Update(userID []byte, clientID, connectionID int);
	SetMaxClient(maxClient int);
	Insert(userID []byte, clientID, connectionID int) bool;
	Remove(userID string, clientID int);
	AuthData() []byte;
}
