package addrx

import (
	"github.com/ProxyPanel/VNet-SSR/utils/langx"
	"github.com/pkg/errors"
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

func GetNetworkFromAddr(addr net.Addr) string {
	return addr.Network()
}

func ParseAddrFromString(network, addr string) (net.Addr, error) {
	var addrConvert net.Addr
	var err error
	switch network {
	case "tcp", "tcp4", "tcp6":
		addrConvert, err = net.ResolveTCPAddr(network, addr)
	case "udp", "udp4", "udp6":
		addrConvert, err = net.ResolveUDPAddr(network, addr)
	}
	if err != nil {
		return nil, err
	}
	return addrConvert, nil
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
		return "", errors.Wrap(err, "public ip request error")
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return "", errors.Errorf("public ip status: %d", res.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, 128))
	if err != nil {
		return "", errors.Wrap(err, "read public ip error")
	}

	ip := strings.TrimSpace(string(body))
	if parsed := net.ParseIP(ip); parsed == nil {
		return "", errors.Errorf("public ip is not an address: %q", ip)
	}

	return ip, nil
}

// func GetAddressType(addrx string) string {
// 	var (
// 		ipv4   = `^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):?([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]?)$`
// 		ipv6   = `^(([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)):?([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]?)$`
// 		domain = `^(?=.{1,255}$)[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?(?:\.[0-9A-Za-z](?:(?:[0-9A-Za-z]|\b-){0,61}[0-9A-Za-z])?)*\.?:?([0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5]?)$`
// 	)
// }
