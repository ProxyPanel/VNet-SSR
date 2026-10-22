package network

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/ProxyPanel/VNet-SSR/common/ciphers"
	"github.com/ProxyPanel/VNet-SSR/common/obfs"
	"github.com/ProxyPanel/VNet-SSR/core"
)

type oneDatagramConn struct {
	payload []byte
}

func (c *oneDatagramConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n := copy(p, c.payload)
	return n, &net.UDPAddr{IP: net.ParseIP("203.0.113.9"), Port: 40000}, nil
}

func (c *oneDatagramConn) WriteTo([]byte, net.Addr) (int, error) { return 0, nil }
func (c *oneDatagramConn) Close() error                          { return nil }
func (c *oneDatagramConn) LocalAddr() net.Addr                   { return &net.UDPAddr{IP: net.IPv4zero, Port: 8388} }
func (c *oneDatagramConn) SetDeadline(time.Time) error           { return nil }
func (c *oneDatagramConn) SetReadDeadline(time.Time) error       { return nil }
func (c *oneDatagramConn) SetWriteDeadline(time.Time) error      { return nil }

type udpCaptureTraffic struct {
	uploads int
}

func (c *udpCaptureTraffic) Upload(int, int64)     { c.uploads++ }
func (c *udpCaptureTraffic) Download(int, int64)   {}
func (c *udpCaptureTraffic) IdentityToUid(int) int { return 0 }

type udpCaptureLimiter struct {
	allowUps int
}

func (c *udpCaptureLimiter) DownLimit(int, int) error { return nil }
func (c *udpCaptureLimiter) UpLimit(int, int) error   { return nil }
func (c *udpCaptureLimiter) AllowUp(int, int) bool    { c.allowUps++; return true }
func (c *udpCaptureLimiter) AllowDown(int, int) bool  { return true }

// newUDPTestDecorate 按读取方向封装一段密文：payload 是 SS 解密之后、协议解包之前的字节。
// 多端口（single=0）下身份就是监听端口，正是未认证包会被记到某个账号上的那条路径。
func newUDPTestDecorate(t *testing.T, protocol string, payload []byte) (*ShadowsocksRDecorate, *udpCaptureTraffic, *udpCaptureLimiter) {
	t.Helper()

	const method = "aes-256-cfb"

	// SetServerInfo 会按 protocol_param 落并发上限，读的是全局单例
	core.GetApp().SetObfsProtocolService(obfs.NewObfsAuthChainData(protocol))

	enc, err := ciphers.NewEncryptor(method, "killer")
	if err != nil {
		t.Fatalf("建加密器失败: %s", err.Error())
	}
	ciphertext, err := enc.EncryptAll(payload, enc.MustNewIV())
	if err != nil {
		t.Fatalf("封装失败: %s", err.Error())
	}

	req := NewRequestWithUDP(&oneDatagramConn{payload: ciphertext})
	ssrd, err := NewShadowsocksRDecorate(req, "plain", method, "killer", protocol, "", "64", "127.0.0.1", 8388, false, 0, nil)
	if err != nil {
		t.Fatalf("建装饰器失败: %s", err.Error())
	}

	rep, limiter := &udpCaptureTraffic{}, &udpCaptureLimiter{}
	ssrd.TrafficReport = rep
	ssrd.ILimiter = limiter

	return ssrd, rep, limiter
}

// 流密码没有完整性校验：任意密文都能解出字节，协议层 MAC 是唯一的认证判据。
// 认证失败时协议返回空结果，这条数据报既不能归属账号、也不能当转发请求，更不能先记账。
func TestUnauthenticatedUDPDatagramIsNotAccounted(t *testing.T) {
	garbage := bytes.Repeat([]byte{0x5a}, 64)
	ssrd, rep, limiter := newUDPTestDecorate(t, "auth_chain_a", garbage)

	data, _, _, err := ssrd.ReadFrom()
	if err == nil {
		t.Fatalf("未认证包应返回丢包判据，实际解出 %d 字节并当作转发请求", len(data))
	}
	if rep.uploads != 0 {
		t.Fatalf("未认证包被记了 %d 次上传", rep.uploads)
	}
	if limiter.allowUps != 0 {
		t.Fatalf("未认证包被扣了 %d 次限速", limiter.allowUps)
	}
}

// 反向对照：认证通过的包仍要记账并过限速，不能在入口把整条 UDP 通路一起挡掉。
func TestAuthenticatedUDPDatagramIsStillAccounted(t *testing.T) {
	const method = "aes-256-cfb"

	enc, err := ciphers.NewEncryptor(method, "killer")
	if err != nil {
		t.Fatalf("建加密器失败: %s", err.Error())
	}
	client, err := obfs.GetObfs("auth_chain_a")
	if err != nil {
		t.Fatalf("取客户端协议失败: %s", err.Error())
	}
	s := obfs.NewServerInfo()
	s.SetKey(enc.Key)
	s.SetProtocolParam("")
	s.SetSingle(0)
	client.SetServerInfo(s)

	packet, err := client.ClientUDPPreEncrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("客户端 UDP 封装失败: %s", err.Error())
	}

	ssrd, rep, limiter := newUDPTestDecorate(t, "auth_chain_a", packet)

	data, uid, _, err := ssrd.ReadFrom()
	if err != nil {
		t.Fatalf("认证通过的包被丢弃: %s", err.Error())
	}
	if string(data) != "hello" {
		t.Fatalf("解出 %q, want hello", string(data))
	}
	if len(uid) == 0 {
		t.Fatal("多端口下这条包应带上监听端口作为归属身份")
	}
	if rep.uploads == 0 {
		t.Fatal("认证通过的包没有记账")
	}
	if limiter.allowUps == 0 {
		t.Fatal("认证通过的包没有过限速")
	}
}
