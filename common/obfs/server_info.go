package obfs

import "net"

const (
	NETWORK_MTU      = 1500
	TCP_MSS          = 1460
	BUF_SIZE         = 32 * 1024
	UDP_MAX_BUF_SIZE = 65536
	DEFAULT_HEAD_LEN = 30
)

type ServerInfo interface {
	GetHost() string
	SetHost(host string)
	GetPort() int
	SetPort(port int)
	GetClient() net.IP
	SetClient(client net.IP)
	GetClientPort() int
	SetClientPort(port int)
	GetProtocolParam() string
	SetProtocolParam(protocolParam string)
	GetObfsParam() string
	SetObfsParam(obfsParam string)
	SetIv(iv []byte)
	GetIv() []byte
	SetRecvIv(iv []byte)
	GetRecvIv() []byte
	SetKeyStr(key string)
	GetKeyStr() string
	SetKey(key []byte)
	GetKey() []byte
	SetHeadLen(len int)
	GetHeadLen() int
	SetTCPMss(mss int)
	GetTCPMss() int
	SetBufferSize(size int)
	GetBufferSize() int
	SetOverhead(size int)
	GetOverhead() int
	GetUsers() *UserTable
	SetUsers(users *UserTable)
	// GetSingle 是节点的端口模式：1 = 单端口。密码表为空在两种模式下含义不同，
	// 不能用表长推断模式
	GetSingle() int
	SetSingle(single int)
	// Identity 是本会话默认归属的账号身份（4 字节小端）：多端口下就是监听端口，
	// 供连接计数桶取键用；单端口下由 auth 包解出后写回会话，这里留空
	GetIdentity() []byte
	SetIdentity(identity []byte)
	UpdateUser(uid []byte)
	SetUpdateUserFunc(func(uid []byte))
}

type serverInfo struct {
	Host          string
	Port          int
	Client        net.IP
	ClientPort    int
	ProtocolParam string
	ObfsParam     string
	Iv            []byte
	RecvIv        []byte
	KeyStr        string
	Key           []byte
	HeadLen       int
	TCPMss        int
	BufferSize    int
	Overhead      int
	Users         *UserTable
	Single        int
	Identity      []byte
	updateUser    func(uid []byte)
}

// InitServerInfo init ServerInfo default value
func NewServerInfo() ServerInfo {
	return &serverInfo{
		TCPMss:  TCP_MSS,
		HeadLen: DEFAULT_HEAD_LEN,
		Users:   NewUserTable(),
	}
}

func (s *serverInfo) GetHost() string {
	return s.Host
}

func (s *serverInfo) SetHost(host string) {
	s.Host = host
}

func (s *serverInfo) GetPort() int {
	return s.Port
}

func (s *serverInfo) SetPort(port int) {
	s.Port = port
}

func (s *serverInfo) GetClient() net.IP {
	return s.Client
}

func (s *serverInfo) SetClient(client net.IP) {
	s.Client = client
}

func (s *serverInfo) GetClientPort() int {
	return s.ClientPort
}

func (s *serverInfo) SetClientPort(port int) {
	s.ClientPort = port
}

func (s *serverInfo) GetProtocolParam() string {
	return s.ProtocolParam
}

func (s *serverInfo) SetProtocolParam(protocolParam string) {
	s.ProtocolParam = protocolParam
}

func (s *serverInfo) GetObfsParam() string {
	return s.ObfsParam
}

func (s *serverInfo) SetObfsParam(obfsParam string) {
	s.ObfsParam = obfsParam
}

func (s *serverInfo) SetIv(iv []byte) {
	s.Iv = iv
}

func (s *serverInfo) GetIv() []byte {
	return s.Iv
}

func (s *serverInfo) SetRecvIv(iv []byte) {
	s.RecvIv = iv
}

func (s *serverInfo) GetRecvIv() []byte {
	return s.RecvIv
}

func (s *serverInfo) SetKeyStr(key string) {
	s.KeyStr = key
}

func (s *serverInfo) GetKeyStr() string {
	return s.KeyStr
}

func (s *serverInfo) SetKey(key []byte) {
	s.Key = key
}

func (s *serverInfo) GetKey() []byte {
	return s.Key
}

func (s *serverInfo) SetHeadLen(len int) {
	s.HeadLen = len
}

func (s *serverInfo) GetHeadLen() int {
	return s.HeadLen
}

func (s *serverInfo) SetTCPMss(mss int) {
	s.TCPMss = mss
}

func (s *serverInfo) GetTCPMss() int {
	return s.TCPMss
}

func (s *serverInfo) SetBufferSize(size int) {
	s.BufferSize = size
}

func (s *serverInfo) GetBufferSize() int {
	return s.BufferSize
}

func (s *serverInfo) SetOverhead(size int) {
	s.Overhead = size
}

func (s *serverInfo) GetOverhead() int {
	return s.Overhead
}

func (s *serverInfo) GetUsers() *UserTable {
	return s.Users
}

func (s *serverInfo) SetUsers(users *UserTable) {
	if users == nil {
		users = NewUserTable()
	}
	s.Users = users
}

func (s *serverInfo) GetSingle() int {
	return s.Single
}

func (s *serverInfo) SetSingle(single int) {
	s.Single = single
}

func (s *serverInfo) GetIdentity() []byte {
	return s.Identity
}

func (s *serverInfo) SetIdentity(identity []byte) {
	s.Identity = identity
}

func (s *serverInfo) UpdateUser(uid []byte) {
	if s.updateUser != nil {
		s.updateUser(uid)
	}
}

func (s *serverInfo) SetUpdateUserFunc(f func([]byte)) {
	s.updateUser = f
}
