package obfs

import (
	"bytes"
	"testing"
)

func newHTTPTestInfo() ServerInfo {
	s := NewServerInfo()
	s.SetHost("example.com")
	s.SetPort(8080)
	s.SetIv([]byte("0123456789abcdef"))
	s.SetKey([]byte("key"))
	s.SetHeadLen(30)
	return s
}

func TestHttpPostRoundTrip(t *testing.T) {
	info := newHTTPTestInfo()
	client, err := GetObfs("http_post")
	if err != nil {
		t.Fatal(err)
	}
	server, err := GetObfs("http_post")
	if err != nil {
		t.Fatal(err)
	}
	client.SetServerInfo(info)
	server.SetServerInfo(info)

	payload := bytes.Repeat([]byte("S"), 48)
	encoded, err := client.ClientEncode(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(encoded, []byte("POST /")) {
		t.Fatalf("首包应是 POST 请求行，实得 %q", encoded[:16])
	}
	if !bytes.Contains(encoded, []byte("Content-Type: multipart/form-data; boundary=")) {
		t.Fatal("缺 multipart 边界头")
	}

	decoded, _, _, err := server.ServerDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("回环不符：解码得 %d 字节，期望 %d 字节", len(decoded), len(payload))
	}
}

func TestHttpPostNotMatchPassesBufferThrough(t *testing.T) {
	info := newHTTPTestInfo()
	server, err := GetObfs("http_post")
	if err != nil {
		t.Fatal(err)
	}
	server.SetServerInfo(info)

	garbage := []byte("HELLO /not-an-ssr-request HTTP/1.1\r\nHost: x\r\n\r\n")
	out, needDecrypt, _, err := server.ServerDecode(garbage)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, garbage) || !needDecrypt {
		t.Fatalf("http_post 兜底应原样透传，实得 %q needDecrypt=%v", out[:24], needDecrypt)
	}
}

func TestTlsFastAuthDegradesToPlainOnBadAuth(t *testing.T) {
	info := newHTTPTestInfo()
	client, err := GetObfs("tls1.2_ticket_fastauth")
	if err != nil {
		t.Fatal(err)
	}
	server, err := GetObfs("tls1.2_ticket_fastauth")
	if err != nil {
		t.Fatal(err)
	}
	client.SetServerInfo(info)
	server.SetServerInfo(info)

	hello, err := client.ClientEncode(nil)
	if err != nil {
		t.Fatal(err)
	}

	// 服务端密钥对不上：严格模式会回 E*2048 并退出手握手，fastauth 必须降级放行
	bad := NewServerInfo()
	bad.SetHost("example.com")
	bad.SetPort(8080)
	bad.SetIv(info.GetIv())
	bad.SetKey([]byte("different-key"))
	bad.SetHeadLen(30)
	server.SetServerInfo(bad)

	out, needDecrypt, _, err := server.ServerDecode(hello)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, hello) || !needDecrypt {
		t.Fatalf("fastauth 校验失败应原样透传，实得 %d 字节 needDecrypt=%v", len(out), needDecrypt)
	}

	next := []byte("plain payload after degrade")
	out2, needDecrypt2, _, err := server.ServerDecode(next)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out2, next) || !needDecrypt2 {
		t.Fatal("降级后续包必须持续透传")
	}
}
