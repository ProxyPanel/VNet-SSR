package obfs

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

func ExampleNewHttpSimple() {
	plain, _ := NewHttpSimple("http_simple")
	h := plain.(*HttpSimple)
	data := h.encodeHead([]byte("helloa"))
	fmt.Print(hex.EncodeToString(data))
	//Output:
	//253638253635253663253663253666253631
}

// obfs_param 的「#」后段是客户端伪造的响应体，不参与 Host 白名单。
// 服务端不剥掉它就只会拿整串去比，带自定义头的 param 等于把正常连接全杀
func TestHttpSimpleObfsParamHashKeepsHostWhitelist(t *testing.T) {
	newSide := func() Plain {
		p, err := GetObfs("http_simple")
		if err != nil {
			t.Fatalf("http_simple 未注册: %v", err)
		}
		s := NewServerInfo()
		s.SetObfsParam("a.com#X-Test: 1\nX-From: ssr")
		s.SetHost("example.com")
		s.SetPort(80)
		s.SetIv(MustHexDecode("271d7f17d03ed7cd1f44327456aebfa2"))
		s.SetHeadLen(30)
		p.SetServerInfo(s)
		return p
	}
	client, server := newSide(), newSide()

	payload := bytes.Repeat([]byte("abcdefgh"), 12)
	encoded, err := client.ClientEncode(payload)
	if err != nil {
		t.Fatalf("客户端封装失败: %v", err)
	}
	if !bytes.HasPrefix(encoded, []byte("GET /")) {
		t.Fatalf("客户端没造出 HTTP 请求头，首 8 字节 %q", encoded[:8])
	}
	if !bytes.Contains(encoded, []byte("X-From: ssr")) {
		t.Fatal("param 的 # 后段没被写成伪造头部")
	}

	decoded, _, _, err := server.ServerDecode(encoded)
	if err != nil {
		t.Fatalf("服务端解包失败: %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("回环不符：payload %d 字节，解出 %d 字节；解成 2048 个 E 就是白名单误杀",
			len(payload), len(decoded))
	}
}
