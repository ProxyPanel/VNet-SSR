package obfs

import (
	"testing"

	"github.com/ProxyPanel/VNet-SSR/core"
)

// 未注册的名字必须回 error：nil 工厂调用会在每条连接里 panic，被连接级 recover 吞成一行日志，
// 面板侧只剩「心跳正常、在线为 0」，管理员看不出是算法名选了节点没实现的那个。
func TestGetObfsRejectsUnregisteredNames(t *testing.T) {
	core.GetApp().SetObfsProtocolService(NewObfsAuthChainData("origin"))

	for _, name := range []string{"auth_chain_b", "auth_chain_c", "auth_sha1_v4", "http_post", "random_head", "tls1.2_ticket_fastauth", ""} {
		plain, err := GetObfs(name)
		if err == nil || plain != nil {
			t.Fatalf("%q 未注册却拿到了实例: %v %v", name, plain, err)
		}
	}
}

// auth_* 系列工厂要全局的 protocol service（main 在取到 nodeInfo 之后才装配），所以先装上再逐个构造
func TestGetObfsBuildsEveryRegisteredName(t *testing.T) {
	core.GetApp().SetObfsProtocolService(NewObfsAuthChainData("origin"))

	for _, name := range []string{"origin", "plain", "http_simple", "tls1.2_ticket_auth", "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a"} {
		plain, err := GetObfs(name)
		if err != nil || plain == nil {
			t.Fatalf("%q 应当可用: %v %v", name, plain, err)
		}
	}
}
