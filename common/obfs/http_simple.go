package obfs

import (
	"bytes"
	"encoding/hex"
	"github.com/ProxyPanel/VNet-SSR/utils/arrayx"
	"github.com/ProxyPanel/VNet-SSR/utils/bytesx"
	"github.com/ProxyPanel/VNet-SSR/utils/randomx"
	"github.com/sirupsen/logrus"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func init() {
	registerMethod("http_simple", NewHttpSimple)
}

var USER_AGENT = []string{
	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0",
	"Mozilla/5.0 (Windows NT 6.3; WOW64; rv:40.0) Gecko/20100101 Firefox/44.0",
	"Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/535.11 (KHTML, like Gecko) Ubuntu/11.10 Chromium/27.0.1453.93 Chrome/27.0.1453.93 Safari/537.36",
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:35.0) Gecko/20100101 Firefox/35.0",
	"Mozilla/5.0 (compatible; WOW64; MSIE 10.0; Windows NT 6.2)",
	"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US) AppleWebKit/533.20.25 (KHTML, like Gecko) Version/5.0.4 Safari/533.20.27",
	"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C)",
	"Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko",
	"Mozilla/5.0 (Linux; Android 4.4; Nexus 5 Build/BuildID) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Mobile Safari/537.36",
	"Mozilla/5.0 (iPad; CPU OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3",
}

func strMatchBegin(str1, str2 string) bool {
	if len(str1) >= len(str2) {
		if str1[:len(str2)] == str2 {
			return true
		}
	}
	return false
}

type HttpSimple struct {
	Plain
	hasSentHeader bool
	hasRecvHeader bool
	host          string
	port          int
	recvBuf       []byte
}

func NewHttpSimple(method string) (Plain, error) {
	newPlain, err := NewPlain(method)
	if err != nil {
		return nil, err
	}
	return &HttpSimple{
		Plain: newPlain,
	}, nil
}

func (h *HttpSimple) encodeHead(buf []byte) []byte {
	hexStr := []byte(hex.EncodeToString(buf))
	chs := make([]byte, 0, len(hexStr))
	for i := 0; i < len(hexStr); i += 2 {
		chs = append(chs, bytesx.ContactSlice([]byte("%"), hexStr[i:i+2])...)
	}
	return chs
}

func (h *HttpSimple) getDataFromHttpHeader(buf []byte) (result []byte, err error) {
	result = []byte{}
	lines := strings.Split(string(buf), "\r\n")
	if len(lines) > 1 {
		hexItems := strings.Split(lines[0], "%")
		if len(hexItems) > 1 {
			for i, item := range hexItems {
				if i == 0 {
					continue
				}
				if len(hexItems) < 2 {
					data, err := hex.DecodeString("0" + item)
					if err != nil {
						return nil, err
					}
					result = bytesx.ContactSlice(result, data)
					break
				} else if len(item) > 2 {
					data, err := hex.DecodeString(item[:2])
					if err != nil {
						return nil, err
					}
					result = bytesx.ContactSlice(result, data)
					break
				} else {
					data, err := hex.DecodeString(item)
					if err != nil {
						return nil, err
					}
					result = bytesx.ContactSlice(result, data)
				}
			}
			return result, nil
		}
	}
	return []byte{}, nil
}

func (h *HttpSimple) getHostFromHttpHeader(buf []byte) string {
	lines := strings.Split(string(buf), "\r\n")
	if len(lines) > 1 {
		for _, line := range lines {
			if strMatchBegin(line, "Host: ") {
				return line[6:]
			}
		}
	}
	return ""
}

func (h *HttpSimple) notMatchReturn(buf []byte) ([]byte, bool, bool, error) {
	h.hasSentHeader = true
	h.hasRecvHeader = true
	if h.GetMethod() == "http_simple" {
		return bytes.Repeat([]byte("E"), 2048), false, false, nil
	}
	return buf, true, false, nil
}

func (h *HttpSimple) errorReturn(buf []byte) ([]byte, bool, bool, error) {
	h.hasSentHeader = true
	h.hasRecvHeader = true
	return bytes.Repeat([]byte("E"), 2048), false, false, nil
}

func (h *HttpSimple) ClientEncode(buf []byte) ([]byte, error) {
	if h.hasSentHeader {
		return buf, nil
	}

	headSize := len(h.GetServerInfo().GetIv()) + h.GetServerInfo().GetHeadLen()
	var headLen int
	if len(buf)-headSize > 64 {
		headLen = headSize + randomx.RandIntRange(0, 64)
	} else {
		headLen = len(buf)
	}
	headData := buf[:headLen]
	buf = buf[headLen:]
	port := []byte{}
	if h.GetServerInfo().GetPort() != 80 {
		port = bytesx.ContactSlice([]byte(":"), []byte(strconv.Itoa(h.GetServerInfo().GetPort())))
	}
	body := []byte{}
	hosts := ""
	if h.GetServerInfo().GetObfsParam() != "" {
		hosts = h.GetServerInfo().GetObfsParam()
	} else {
		hosts = h.GetServerInfo().GetHost()
	}
	pos := strings.Index(hosts, "#")
	if pos >= 0 {
		body = []byte(strings.ReplaceAll(hosts[pos+1:], "\n", "\r\n"))
		body = []byte(strings.ReplaceAll(string(body), "\\n", "\r\n"))
		hosts = hosts[:pos]
	}
	hostArr := strings.Split(hosts, ",")
	host := randomx.RandomStringsChoice(hostArr)
	httpHead := bytesx.ContactSlice([]byte("GET /"), h.encodeHead(headData), []byte(" HTTP/1.1\r\n"))
	httpHead = bytesx.ContactSlice(httpHead, []byte("Host: "), []byte(host), port, []byte("\r\n"))
	if len(body) > 0 {
		httpHead = bytesx.ContactSlice(httpHead, body, []byte("\r\n\r\n"))
	} else {
		httpHead = bytesx.ContactSlice(httpHead, []byte("User-Agent: "),
			[]byte(randomx.RandomStringsChoice(USER_AGENT)),
			[]byte("\r\n"))
		httpHead = bytesx.ContactSlice(httpHead, []byte("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\n\r\n"))
	}
	h.hasSentHeader = true
	return bytesx.ContactSlice(httpHead, buf), nil
}

func (h *HttpSimple) ClientDecode(buf []byte) ([]byte, bool, error) {
	if h.hasRecvHeader {
		return buf, false, nil
	}
	pos := strings.Index(string(buf), "\r\n\r\n")
	if pos >= 0 {
		h.hasRecvHeader = true
		return buf[pos+4:], false, nil
	} else {
		return []byte{}, false, nil
	}
}

func (h *HttpSimple) ServerEncode(buf []byte) ([]byte, error) {
	if h.hasSentHeader {
		return buf, nil
	}

	header := "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Encoding: gzip\r\nContent-Type: text/html\r\nDate: "
	header += time.Now().Format(http.TimeFormat)
	header += "\r\nServer: nginx\r\nVary: Accept-Encoding\r\n\r\n"
	h.hasSentHeader = true
	return bytesx.ContactSlice([]byte(header), buf), nil

}

func (h *HttpSimple) ServerDecode(buf []byte) ([]byte, bool, bool, error) {
	if h.hasRecvHeader {
		return buf, true, false, nil
	}
	h.recvBuf = bytesx.ContactSlice(h.recvBuf, buf)
	buf = h.recvBuf
	if len(buf) > 10 {
		if strMatchBegin(string(buf), "GET ") || strMatchBegin(string(buf), "POST ") {
			if len(buf) > 65536 {
				h.recvBuf = []byte{}
				logrus.Warning("http_simple: over size")
				return h.notMatchReturn(buf)
			}
		} else {
			h.recvBuf = []byte{}
			logrus.Warning("http_simple: not match begin")
			return h.notMatchReturn(buf)
		}
	} else {
		return []byte{}, true, false, nil
	}

	if strings.Index(string(buf), "\r\n\r\n") >= 0 {
		datas := strings.Split(string(buf), "\r\n\r\n")
		resultBuf, err := h.getDataFromHttpHeader(buf)
		if err != nil {
			return h.errorReturn(buf)
		}
		host := h.getHostFromHttpHeader(buf)

		if len(host) > 0 && len(h.GetServerInfo().GetObfsParam()) > 0 {
			pos := strings.Index(host, ":")
			if pos >= 0 {
				host = host[:pos]
			}
			hosts := strings.Split(h.GetServerInfo().GetObfsParam(), ",")
			if !arrayx.FindStringInArray(host, hosts) {
				return h.notMatchReturn(buf)
			}
		}

		if len(resultBuf) < 4 {
			return h.errorReturn(buf)
		}

		if len(datas) > 1 {
			resultBuf = bytesx.ContactSlice(resultBuf, []byte(datas[1]))
		}

		if len(resultBuf) >= 13 {
			h.hasRecvHeader = true
			return resultBuf, true, false, nil
		}

		return h.notMatchReturn(buf)
	} else {
		return []byte{}, true, false, nil
	}
}
