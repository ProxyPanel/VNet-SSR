package obfs

import (
	"testing"

	"github.com/ProxyPanel/VNet-SSR/utils/binaryx"
)

// auth_chain_a 的 UDP 通路：服务端要从包里认出账号（uid 随包带出，4 字节小端），
// 再把响应按同一个 uid 封回去。TCP 的补全表另有测试，这条 UDP 通路只在这里被覆盖。
func TestAuthChainAUdpRoundTrip(t *testing.T) {
	client, server := newChainPair(t, "auth_chain_a")
	// 解出首个 UDP 包时服务端回调登记用户；生产路径由 service 提供，这里给个空实现
	server.GetServerInfo().SetUpdateUserFunc(func([]byte) {})

	payload := []byte("hello")

	ciphered, err := client.ClientUDPPreEncrypt(payload)
	if err != nil {
		t.Fatalf("客户端 UDP 封装失败: %v", err)
	}

	clear, uid, err := server.ServerUDPPostDecrypt(ciphered)
	if err != nil {
		t.Fatalf("服务端 UDP 解包失败: %v", err)
	}
	if string(clear) != string(payload) {
		t.Fatalf("服务端解出 %q, want %q", clear, payload)
	}
	if got := binaryx.LEBytesToUInt32([]byte(uid)); got != 1024 {
		t.Fatalf("包里的 uid 解出 %d, want 1024", got)
	}

	responded, err := server.ServerUDPPreEncrypt(payload, []byte(uid))
	if err != nil {
		t.Fatalf("服务端 UDP 封装失败: %v", err)
	}
	clear, err = client.ClientUDPPostDecrypt(responded)
	if err != nil {
		t.Fatalf("客户端 UDP 解包失败: %v", err)
	}
	if string(clear) != string(payload) {
		t.Fatalf("客户端解出 %q, want %q", clear, payload)
	}
}
