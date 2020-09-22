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

type HostFirewall interface {
	JudgeHostWithReport(ipOrDomain string, uid int) bool
}

type ObfsProtocolService interface {
	Update(userID []byte, clientID, connectionID int);
	SetMaxClient(maxClient int);
	Insert(userID []byte, clientID, connectionID int) bool;
	Remove(userID string, clientID int);
	AuthData() []byte;
}
