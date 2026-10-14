package obfs

import (
	"testing"

	"github.com/ProxyPanel/VNet-SSR/core"
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

// 校验位不对就必须整包丢弃。校验位只截 1 字节（上游格式），改正文有 1/256 概率碰巧对上，
// 所以这里直接改校验位本身，判据才是确定的
func TestAuthChainUDPBadChecksumDropped(t *testing.T) {
	client, server := newChainPair(t, "auth_chain_a")

	ciphered, err := client.ClientUDPPreEncrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("客户端 UDP 封装失败: %v", err)
	}
	if clear, _, err := server.ServerUDPPostDecrypt(append([]byte{}, ciphered...)); err != nil || len(clear) == 0 {
		t.Fatalf("未篡改的包没通过：clear %q err %v", clear, err)
	}

	bad := append([]byte{}, ciphered...)
	bad[len(bad)-1] ^= 0xFF
	clear, uid, err := server.ServerUDPPostDecrypt(bad)
	if err != nil {
		t.Fatalf("校验位不对不该抛错: %v", err)
	}
	if len(clear) != 0 || uid != "" {
		t.Fatalf("校验位不对的包被接受了：clear %q uid %q", clear, uid)
	}
}

// 表非空却没有这个身份：没有任何 key 能验证这个包，整包丢弃。
// 拿一个「对不上的 key」去赌校验位，等于给伪造包留 1/256 的通行概率
func TestAuthChainUDPUknownIdentityDropped(t *testing.T) {
	core.GetApp().SetObfsProtocolService(NewObfsAuthChainData("auth_chain_a"))
	known := map[string]string{string(binaryx.LEUint32ToBytes(1024)): "killer"}
	client := newChainSide(t, "auth_chain_a", known, "9999:killer")
	server := newChainSide(t, "auth_chain_a", known, "1024:killer")

	ciphered, err := client.ClientUDPPreEncrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("客户端 UDP 封装失败: %v", err)
	}
	clear, uid, err := server.ServerUDPPostDecrypt(ciphered)
	if err != nil {
		t.Fatalf("不该抛错: %v", err)
	}
	if len(clear) != 0 || uid != "" {
		t.Fatalf("认不出的身份仍被放行：clear %q uid %q", clear, uid)
	}
}

// 空密码条目不算账号：本后端写入侧就拒绝空密码（等于开放账号），表里出现它只能是手改配置，
// 按不认识处理，不能拿空 key 给任何人放行
func TestAuthChainUDPIgnoresEmptyPasswordEntry(t *testing.T) {
	core.GetApp().SetObfsProtocolService(NewObfsAuthChainData("auth_chain_a"))
	emptyPasswd := map[string]string{string(binaryx.LEUint32ToBytes(1024)): ""}
	client := newChainSide(t, "auth_chain_a", emptyPasswd, "1024:")
	server := newChainSide(t, "auth_chain_a", emptyPasswd, "1024:")

	ciphered, err := client.ClientUDPPreEncrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("客户端 UDP 封装失败: %v", err)
	}
	clear, uid, err := server.ServerUDPPostDecrypt(ciphered)
	if err != nil {
		t.Fatalf("不该抛错: %v", err)
	}
	if len(clear) != 0 || uid != "" {
		t.Fatalf("空密码条目被当成账号放行了：clear %q uid %q", clear, uid)
	}
}
