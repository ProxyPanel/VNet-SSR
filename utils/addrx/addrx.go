package addrx

import (
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/utils/langx"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func GetIPFromAddr(addr net.Addr) string {
	switch addr.(type) {
	case *net.TCPAddr:
		tcpAddr := addr.(*net.TCPAddr)
		return tcpAddr.IP.String()
	case *net.UDPAddr:
		udpAddr := addr.(*net.UDPAddr)
		return udpAddr.IP.String()
	case nil:
		return ""
	default:
		return ""
	}
}

func GetPortFromAddr(addr net.Addr) int {
	switch addr.(type) {
	case *net.TCPAddr:
		tcpAddr := addr.(*net.TCPAddr)
		return tcpAddr.Port
	case *net.UDPAddr:
		udpAddr := addr.(*net.UDPAddr)
		return udpAddr.Port
	case nil:
		return 0
	default:
		return 0
	}
}

func SplitIpFromAddr(addr string) string {
	ip, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return ip
}

func SplitPortFromAddr(addr string) int {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	return langx.FirstResult(strconv.Atoi, port).(int)
}

// GetPublicIp 按指定探测地址取本机对外地址；地址决定看到哪一族（v4 或 v6）。
// 结果必须过 net.ParseIP：限流时这些站点会回 HTML，非空不代表拿到了地址。
func GetPublicIp(url string) (string, error) {
	client := http.Client{Timeout: 3 * time.Second}

	res, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("%s: %w", "public ip request error", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("public ip status: %d", res.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, 128))
	if err != nil {
		return "", fmt.Errorf("%s: %w", "read public ip error", err)
	}

	ip := strings.TrimSpace(string(body))
	if parsed := net.ParseIP(ip); parsed == nil {
		return "", fmt.Errorf("public ip is not an address: %q", ip)
	}

	return ip, nil
}
