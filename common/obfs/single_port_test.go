package obfs

import (
	"bytes"
	"testing"

	"github.com/ProxyPanel/VNet-SSR/core"
)

// 单端口下密码表为空只代表「没有有效账号」，不能当成多端口：
// 否则不知道身份的一条流会拿节点密钥通过握手，且不记账、不限速
func TestAuthChainSinglePortEmptyTableRejectsUnknownIdentity(t *testing.T) {
	for _, name := range []string{"auth_chain_a", "auth_aes128_sha1"} {
		core.GetApp().SetObfsProtocolService(NewObfsAuthChainData(name))

		empty := map[string]string{}
		server := newChainSide(t, name, empty, "")
		server.GetServerInfo().SetSingle(1)

		// 客户端把第二段设成节点密钥的派生值：单端口空表下旧实现会接受这条身份
		client := newChainSide(t, name, empty, "9999:"+string(server.GetServerInfo().GetKey()))
		client.GetServerInfo().SetSingle(1)

		payload := bytes.Repeat([]byte("m"), 60)
		encoded, err := client.ClientPreEncrypt(payload)
		if err != nil {
			t.Fatalf("%s 客户端封装失败: %v", name, err)
		}
		decoded, _, err := server.ServerPostDecrypt(encoded)
		if err != nil {
			t.Fatalf("%s 不认识的身份不该抛错: %v", name, err)
		}
		if bytes.Contains(decoded, payload) {
			t.Fatalf("%s 单端口空表把未知身份解出了明文", name)
		}
	}
}

// 反向对照：同样的空表与未知身份，在多端口模式下必须照常握手（端口自己就是账号）
func TestAuthChainMultiPortEmptyTableStillAcceptsUnknownIdentity(t *testing.T) {
	core.GetApp().SetObfsProtocolService(NewObfsAuthChainData("auth_chain_a"))
	empty := map[string]string{}
	client := newChainSide(t, "auth_chain_a", empty, "")
	server := newChainSide(t, "auth_chain_a", empty, "")

	payload := bytes.Repeat([]byte("m"), 60)
	encoded, err := client.ClientPreEncrypt(payload)
	if err != nil {
		t.Fatalf("客户端封装失败: %v", err)
	}
	decoded, _, err := server.ServerPostDecrypt(encoded)
	if err != nil {
		t.Fatalf("服务端解包失败: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("多端口空表回环不符：解出 %q", decoded)
	}
}
