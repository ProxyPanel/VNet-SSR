// Package sniff 在已解密的首包里识别 HTTP 与 TLS，取出 Host/SNI 与请求路径。
// 只窥探不消耗：解析失败或数据不完整时返回空结果，由调用方按目标地址判定。
package sniff

import (
	"bytes"
	"strconv"
)

const (
	ProtocolHTTP = "http"
	ProtocolTLS  = "tls"
)

type Result struct {
	Protocol string
	Host     string // HTTP Host 头或 TLS SNI，取不到为空
	Port     int    // Host 头里显式带端口时才有值
	URL      string // HTTP 请求路径（含 query），仅 http
}

var methods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "),
	[]byte("DELETE "), []byte("OPTIONS "), []byte("CONNECT "),
	[]byte("TRACE "), []byte("PATCH "),
}

func Sniff(data []byte) Result {
	if len(data) == 0 {
		return Result{}
	}
	for _, m := range methods {
		if bytes.HasPrefix(data, m) {
			return sniffHTTP(data)
		}
	}
	if data[0] == 0x16 {
		return sniffTLS(data)
	}
	return Result{}
}

func sniffHTTP(data []byte) Result {
	r := Result{Protocol: ProtocolHTTP}
	lines := bytes.Split(data, []byte("\r\n"))
	if len(lines) == 0 {
		return r
	}
	// 请求行：METHOD SP URI SP VERSION
	if parts := bytes.SplitN(lines[0], []byte(" "), 3); len(parts) >= 2 {
		r.URL = string(parts[1])
	}
	for _, line := range lines[1:] {
		if len(line) == 0 {
			break // 头部结束
		}
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		if bytes.EqualFold(bytes.TrimSpace(name), []byte("Host")) {
			r.Host, r.Port = splitHostPort(string(bytes.TrimSpace(value)))
			break
		}
	}
	return r
}

func splitHostPort(s string) (string, int) {
	// 裸 IPv6（::1）冒号不止一个，按端口切会切错；带端口的 IPv6 必是 [::1]:443 形状
	if bytes.Count([]byte(s), []byte(":")) > 1 && !bytes.HasPrefix([]byte(s), []byte("[")) {
		return s, 0
	}
	if i := bytes.LastIndex([]byte(s), []byte(":")); i > 0 && !bytes.Contains([]byte(s[i:]), []byte("]")) {
		if p, err := strconv.Atoi(s[i+1:]); err == nil {
			return s[:i], p
		}
	}
	return s, 0
}

// sniffTLS 从 ClientHello 里取 SNI；首包不完整（握手记录跨多个 TCP 段）时返回空 Host
func sniffTLS(data []byte) Result {
	r := Result{Protocol: ProtocolTLS}
	// TLS 记录头：type(1) version(2) length(2)
	if len(data) < 5 || data[0] != 0x16 {
		return r
	}
	recLen := int(data[3])<<8 | int(data[4])
	if recLen < 1 || 5+recLen > len(data) {
		return r // 记录不完整，不猜
	}
	hs := data[5 : 5+recLen]
	// 握手头：type(1) length(3)
	if hs[0] != 0x01 || len(hs) < 4 {
		return r
	}
	hsLen := int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3])
	if 4+hsLen > len(hs) {
		return r
	}
	ch := hs[4 : 4+hsLen]
	// ClientHello：version(2) random(32) session_id cipher_suites compression
	pos := 2 + 32
	if pos >= len(ch) {
		return r
	}
	pos += 1 + int(ch[pos]) // session id
	if pos+2 > len(ch) {
		return r
	}
	pos += 2 + (int(ch[pos])<<8 | int(ch[pos+1])) // cipher suites
	if pos+1 > len(ch) {
		return r
	}
	pos += 1 + int(ch[pos]) // compression methods
	if pos+2 > len(ch) {
		return r
	}
	exts := ch[pos+2:]
	for i := 0; i+4 <= len(exts); {
		typ := int(exts[i])<<8 | int(exts[i+1])
		l := int(exts[i+2])<<8 | int(exts[i+3])
		body := exts[i+4:]
		if len(body) < l {
			return r
		}
		if typ == 0x0000 { // server_name
			if l >= 5 {
				nameLen := int(body[3])<<8 | int(body[4])
				if 5+nameLen <= l {
					r.Host = string(body[5 : 5+nameLen])
				}
			}
			return r
		}
		i += 4 + l
	}
	return r
}
