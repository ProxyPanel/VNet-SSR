package obfs

import (
	"sort"

	"github.com/pkg/errors"
)

type PlainFactory func(string) (Plain,error)

// Plain interface
type Plain interface {
	InitData() []byte
	GetMethod() string
	SetMethod(method string)
	GetOverhead(direction bool) int
	GetServerInfo() ServerInfo
	SetServerInfo(s ServerInfo)
	ClientPreEncrypt(buf []byte) ([]byte, error)
	ClientEncode(buf []byte) ([]byte, error)
	ClientDecode(buf []byte) ([]byte, bool, error)
	ClientPostDecrypt(buf []byte) ([]byte, error)
	ServerPreEncrypt(buf []byte) ([]byte, error)
	ServerEncode(buf []byte) ([]byte, error)
	// ServerDecode return buffer_to_recv, is_need_decrypt, is_need_to_encode_and_send_back
	ServerDecode(buf []byte) ([]byte, bool, bool, error)
	ServerPostDecrypt(buf []byte) ([]byte, bool, error)
	ClientUDPPreEncrypt(buf []byte) ([]byte, error)
	ClientUDPPostDecrypt(buf []byte) ([]byte, error)
	ServerUDPPreEncrypt(buf,uid []byte) ([]byte, error)
	ServerUDPPostDecrypt(buf []byte) ([]byte, string, error)
	Dispose()
	GetHeadSize(buf []byte, defaultValue int) int
}

var (
	method_supported = make(map[string]PlainFactory)
)

func registerMethod(method string, factory PlainFactory) {
	method_supported[method] = factory
}

func GetObfs(method string) (Plain,error){
	factory, exist := method_supported[method]
	if !exist { // 直接调用取不到的工厂是 nil 调用：会在每条连接里 panic，被连接级 recover 吞成一行日志，
		// 面板只看到心跳正常、在线为 0，节点侧却已经全线连不上
		return nil, errors.Errorf("unsupported protocol or obfs: %s", method)
	}

	return factory(method)
}

// RegisteredNames 返回注册表里的全部协议/混淆名，供 docs/capabilities.json 生成与漂移检查使用
func RegisteredNames() []string {
	names := make([]string, 0, len(method_supported))

	for name := range method_supported {
		names = append(names, name)
	}

	sort.Strings(names)

	return names
}
