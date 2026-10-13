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
	core.GetApp().SetObfsProtocolService(NewObfsAuthChainData(method))

	p, err := GetObfs(method)
	if err != nil {
		t.Fatalf("%s 未注册: %v", method, err)
	}

	s := NewServerInfo()
	s.GetUsers()[string(binaryx.LEUint32ToBytes(1024))] = keyStr
	s.SetClient(net.ParseIP("127.0.0.1"))
	s.SetPort(8080)
	s.SetProtocolParam("1024:" + keyStr)
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
