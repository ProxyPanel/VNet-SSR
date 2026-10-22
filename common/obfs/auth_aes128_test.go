package obfs

import (
	"bytes"
	"net"
	"testing"

	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/utils/binaryx"
)

// auth_aes128_md5 与 auth_aes128_sha1 的 TCP 通路：两端各自派生的 key 与 recv_id 必须算出同一份，
// 上下行都逐字节还原。这条通路此前只有被门禁压住的样例，改坏时面板侧只表现为「在线、无人」。
func TestAuthAes128RoundTrip(t *testing.T) {
	for _, method := range []string{"auth_aes128_md5", "auth_aes128_sha1"} {
		client, server := newAuthAes128Pair(t, method)
		payload := bytes.Repeat([]byte("hello"), 100)

		ciphered, err := client.ClientPreEncrypt(payload)
		if err != nil {
			t.Fatalf("%s 客户端封装失败: %v", method, err)
		}
		clear, _, err := server.ServerPostDecrypt(ciphered)
		if err != nil {
			t.Fatalf("%s 服务端解包失败: %v", method, err)
		}
		if !bytes.Equal(clear, payload) {
			t.Fatalf("%s 上行回环不符：payload %d 字节，解出 %d 字节", method, len(payload), len(clear))
		}

		responded, err := server.ServerPreEncrypt(payload)
		if err != nil {
			t.Fatalf("%s 服务端封装失败: %v", method, err)
		}
		clear, err = client.ClientPostDecrypt(responded)
		if err != nil {
			t.Fatalf("%s 客户端解包失败: %v", method, err)
		}
		if !bytes.Equal(clear, payload) {
			t.Fatalf("%s 下行回环不符：payload %d 字节，解出 %d 字节", method, len(payload), len(clear))
		}
	}
}

// 换过 key 的一端不能把别人的包原样解出来：校验位在包头上，要么报错要么内容不符
func TestAuthAes128RejectsOtherKey(t *testing.T) {
	client := newAuthAes128Side(t, "auth_aes128_md5", "killer", MustHexDecode("b36d331451a61eb2d76860e00c347396"))
	other := newAuthAes128Side(t, "auth_aes128_md5", "another", MustHexDecode("00112233445566778899aabbccddeeff"))

	payload := []byte("hello hello hello")
	ciphered, err := client.ClientPreEncrypt(payload)
	if err != nil {
		t.Fatalf("客户端封装失败: %v", err)
	}
	if clear, _, err := other.ServerPostDecrypt(ciphered); err == nil && bytes.Equal(clear, payload) {
		t.Fatal("换过 key 的一端仍原样解出了明文，包头校验没起作用")
	}
}

func newAuthAes128Pair(t *testing.T, method string) (Plain, Plain) {
	key := MustHexDecode("b36d331451a61eb2d76860e00c347396")
	return newAuthAes128Side(t, method, "killer", key), newAuthAes128Side(t, method, "killer", key)
}

func newAuthAes128Side(t *testing.T, method, keyStr string, key []byte) Plain {
	t.Helper()
	return newAuthAes128SideWith(t, method, keyStr, key,
		map[string]string{string(binaryx.LEUint32ToBytes(1024)): keyStr}, "1024:"+keyStr)
}

// users 与 param 决定这一端怎么认账号：单端口靠表里的身份编号配 uid:passwd，
// 多端口表恒空、param 不带冒号
func newAuthAes128SideWith(t *testing.T, method, keyStr string, key []byte, users map[string]string, param string) Plain {
	t.Helper()
	core.GetApp().SetObfsProtocolService(NewObfsAuthChainData(method))

	p, err := GetObfs(method)
	if err != nil {
		t.Fatalf("%s 未注册: %v", method, err)
	}

	s := NewServerInfo()
	for uidPack, passwd := range users {
		s.GetUsers().Set(uidPack, passwd)
	}
	s.SetClient(net.ParseIP("127.0.0.1"))
	s.SetPort(8080)
	s.SetProtocolParam(param)
	s.SetIv(MustHexDecode("271d7f17d03ed7cd1f44327456aebfa2"))
	s.SetRecvIv(MustHexDecode("271d7f17d03ed7cd1f44327456aebfa2"))
	s.SetKeyStr(keyStr)
	s.SetKey(key)
	s.SetHeadLen(30)
	s.SetTCPMss(1460)
	s.SetBufferSize(32*1024 - 5 - 4)
	s.SetOverhead(9)
	p.SetServerInfo(s)

	return p
}

// 多端口节点：每个监听端口自己就是一个账号，密码表恒空，两端都按本端口密钥算会话 key、
// 包里的身份编号随包随机，TCP 必须能完成握手
func TestAuthAes128MultiPortEmptyTableRoundTrip(t *testing.T) {
	for _, method := range []string{"auth_aes128_md5", "auth_aes128_sha1"} {
		key := MustHexDecode("b36d331451a61eb2d76860e00c347396")
		client := newAuthAes128SideWith(t, method, "killer", key, map[string]string{}, "64")
		server := newAuthAes128SideWith(t, method, "killer", key, map[string]string{}, "64")
		payload := bytes.Repeat([]byte("hello"), 100)

		ciphered, err := client.ClientPreEncrypt(payload)
		if err != nil {
			t.Fatalf("%s 客户端封装失败: %v", method, err)
		}
		clear, _, err := server.ServerPostDecrypt(ciphered)
		if err != nil {
			t.Fatalf("%s 多端口空表下服务端解包失败: %v", method, err)
		}
		if !bytes.Equal(clear, payload) {
			t.Fatalf("%s 多端口回环不符：payload %d 字节，解出 %d 字节", method, len(payload), len(clear))
		}
	}
}

// 单端口下不认识的线上身份（面板已摘号、客户端还拿旧订阅重连）不该当成错误抛出去：
// 没有 key 能验证这条流，按握手不匹配收尾即可。这里钉住「不抛错」与「不漏明文」
func TestAuthAes128UnknownIdentityFailsQuietly(t *testing.T) {
	key := MustHexDecode("b36d331451a61eb2d76860e00c347396")
	known := map[string]string{string(binaryx.LEUint32ToBytes(1024)): "killer"}
	client := newAuthAes128SideWith(t, "auth_aes128_md5", "killer", key, known, "9999:killer")
	server := newAuthAes128SideWith(t, "auth_aes128_md5", "killer", key, known, "1024:killer")
	server.GetServerInfo().SetSingle(1)

	payload := bytes.Repeat([]byte("hello"), 20)
	ciphered, err := client.ClientPreEncrypt(payload)
	if err != nil {
		t.Fatalf("客户端封装失败: %v", err)
	}
	clear, _, err := server.ServerPostDecrypt(ciphered)
	if err != nil {
		t.Fatalf("不认识的身份不该抛错: %v", err)
	}
	if bytes.Contains(clear, payload) {
		t.Fatal("不认识的身份解出了明文，密码表判据没起作用")
	}
}

// 多端口的 UDP：密码表恒空，两端都按本端口密钥封包。返回的身份归零，上层按监听端口归属
// （LEBytesToUInt32 对空串取 0，handleStageAddr 的 0 判据会跳过按账号记账）
func TestAuthAes128UDPMultiPortRoundTrip(t *testing.T) {
	for _, method := range []string{"auth_aes128_md5", "auth_aes128_sha1"} {
		key := MustHexDecode("b36d331451a61eb2d76860e00c347396")
		client := newAuthAes128SideWith(t, method, "killer", key, map[string]string{}, "64")
		server := newAuthAes128SideWith(t, method, "killer", key, map[string]string{}, "64")

		ciphered, err := client.ClientUDPPreEncrypt([]byte("hello"))
		if err != nil {
			t.Fatalf("%s 客户端 UDP 封装失败: %v", method, err)
		}
		clear, uid, err := server.ServerUDPPostDecrypt(ciphered)
		if err != nil {
			t.Fatalf("%s 多端口空表下服务端 UDP 解包失败: %v", method, err)
		}
		if string(clear) != "hello" {
			t.Fatalf("%s 解出 %q, want %q", method, clear, "hello")
		}
		if uid != "" {
			t.Fatalf("%s 多端口不该带出账号身份: %q", method, uid)
		}
	}
}

// 4 字节校验位盖在它之前的全部字节上：校验位不对就整包丢弃，不能继续解给上层
func TestAuthAes128UDPBadChecksumDropped(t *testing.T) {
	key := MustHexDecode("b36d331451a61eb2d76860e00c347396")
	known := map[string]string{string(binaryx.LEUint32ToBytes(1024)): "killer"}
	client := newAuthAes128SideWith(t, "auth_aes128_md5", "killer", key, known, "1024:killer")
	server := newAuthAes128SideWith(t, "auth_aes128_md5", "killer", key, known, "1024:killer")

	ciphered, err := client.ClientUDPPreEncrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("客户端 UDP 封装失败: %v", err)
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
