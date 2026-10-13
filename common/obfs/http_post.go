package obfs

import (
	"github.com/ProxyPanel/VNet-SSR/utils/bytesx"
	"github.com/ProxyPanel/VNet-SSR/utils/randomx"
	"strconv"
	"strings"
)

func init() {
	registerMethod("http_post", NewHttpPost)
}

const boundaryAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

type HttpPost struct {
	*HttpSimple
}

func NewHttpPost(method string) (Plain, error) {
	simple, err := NewHttpSimple(method)
	if err != nil {
		return nil, err
	}
	h := &HttpPost{HttpSimple: simple.(*HttpSimple)}
	h.notMatchData = h.postNotMatchData
	return h, nil
}

func (h *HttpPost) boundary() []byte {
	raw := randomx.RandomBytes(32)
	out := make([]byte, 32)
	for i, b := range raw {
		out[i] = boundaryAlphabet[int(b)%len(boundaryAlphabet)]
	}
	return out
}

func (h *HttpPost) ClientEncode(buf []byte) ([]byte, error) {
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
	httpHead := bytesx.ContactSlice([]byte("POST /"), h.encodeHead(headData), []byte(" HTTP/1.1\r\n"))
	httpHead = bytesx.ContactSlice(httpHead, []byte("Host: "), []byte(host), port, []byte("\r\n"))
	if len(body) > 0 {
		httpHead = bytesx.ContactSlice(httpHead, body, []byte("\r\n\r\n"))
	} else {
		httpHead = bytesx.ContactSlice(httpHead, []byte("User-Agent: "),
			[]byte(randomx.RandomStringsChoice(USER_AGENT)),
			[]byte("\r\n"))
		httpHead = bytesx.ContactSlice(httpHead, []byte("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.8\r\nAccept-Encoding: gzip, deflate\r\n"))
		httpHead = bytesx.ContactSlice(httpHead, []byte("Content-Type: multipart/form-data; boundary="), h.boundary(), []byte("\r\nDNT: 1\r\n"))
		httpHead = bytesx.ContactSlice(httpHead, []byte("Connection: keep-alive\r\n\r\n"))
	}
	h.hasSentHeader = true
	return bytesx.ContactSlice(httpHead, buf), nil
}

// postNotMatchData 覆盖兜底回包：http_post 与上游一致原样透传，不像 http_simple 回一串 E
func (h *HttpPost) postNotMatchData(buf []byte) ([]byte, bool, bool) {
	return buf, true, false
}
