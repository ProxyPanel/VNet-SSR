package sniff

import (
	"testing"
)

func TestSniffHTTP(t *testing.T) {
	data := []byte("GET /path?q=1 HTTP/1.1\r\nHost: www.example.com:8080\r\nUser-Agent: ss\r\n\r\n")
	r := Sniff(data)
	if r.Protocol != ProtocolHTTP || r.Host != "www.example.com" || r.Port != 8080 || r.URL != "/path?q=1" {
		t.Fatalf("HTTP 首包解析错误: %+v", r)
	}
}

func TestSniffHTTPHostWithoutPort(t *testing.T) {
	r := Sniff([]byte("POST /api HTTP/1.1\r\nhost: example.com\r\n\r\n"))
	if r.Host != "example.com" || r.Port != 0 {
		t.Fatalf("Host 头不带端口时应只取域名: %+v", r)
	}
}

func TestSniffHTTPIPv6Host(t *testing.T) {
	r := Sniff([]byte("GET / HTTP/1.1\r\nHost: [::1]:443\r\n\r\n"))
	if r.Host != "[::1]" || r.Port != 443 {
		t.Fatalf("带括号的 IPv6 Host 解析错误: %+v", r)
	}
	r = Sniff([]byte("GET / HTTP/1.1\r\nHost: ::1\r\n\r\n"))
	if r.Host != "::1" || r.Port != 0 {
		t.Fatalf("裸 IPv6 Host 不该被当成 host:port 切开: %+v", r)
	}
}

func TestSniffTLSClientHello(t *testing.T) {
	r := Sniff(clientHelloWithSNI("news.ycombinator.com"))
	if r.Protocol != ProtocolTLS || r.Host != "news.ycombinator.com" {
		t.Fatalf("SNI 解析错误: %+v", r)
	}
}

func TestSniffTLSIncompleteIsIgnored(t *testing.T) {
	full := clientHelloWithSNI("example.com")
	r := Sniff(full[:len(full)-3]) // 记录被 TCP 段切开
	if r.Protocol != ProtocolTLS || r.Host != "" {
		t.Fatalf("不完整握手不该猜出域名: %+v", r)
	}
}

func TestSniffUnknown(t *testing.T) {
	if r := Sniff([]byte{0x00, 0x11, 0x22}); r.Protocol != "" || r.Host != "" {
		t.Fatalf("非 HTTP/TLS 首包应返回空结果: %+v", r)
	}
	if r := Sniff(nil); r.Protocol != "" {
		t.Fatalf("空数据应返回空结果: %+v", r)
	}
}

// clientHelloWithSNI 拼一个只含 SNI 扩展的最小 ClientHello（含 TLS 记录头与握手头）
func clientHelloWithSNI(name string) []byte {
	sni := []byte{0x00, byte(3 + len(name))}
	sni = append(sni, 0x00) // hostname 类型
	sni = append(sni, byte(len(name)>>8), byte(len(name)))
	sni = append(sni, name...)
	ext := []byte{0x00, 0x00, byte(len(sni)>>8), byte(len(sni))}
	ext = append(ext, sni...)

	ch := []byte{0x03, 0x03}
	ch = append(ch, make([]byte, 32)...)                     // random
	ch = append(ch, 0x00)                                    // session id 长度
	ch = append(ch, 0x00, 0x02, 0x00, 0x2f)                  // 一个密码套件
	ch = append(ch, 0x01, 0x00)                              // 压缩方法
	ch = append(ch, byte(len(ext)>>8), byte(len(ext)))       // 扩展总长
	ch = append(ch, ext...)

	hs := []byte{0x01, byte(len(ch)>>16), byte(len(ch)>>8), byte(len(ch))}
	hs = append(hs, ch...)

	rec := []byte{0x16, 0x03, 0x01, byte(len(hs)>>8), byte(len(hs))}
	return append(rec, hs...)
}
