package network

import (
	"bytes"
	"net"
	"testing"
	"time"
	"unsafe"

	"github.com/ProxyPanel/VNet-SSR/utils/binaryx"
)

// 名单外的算法名必须在这里就回错误：过去是 nil 工厂被调用，每条连接里 panic 一次，
// 被连接级 recover 吞成一行日志，面板只看到心跳正常、在线为 0
func TestNewDecorateRejectsUnknownAlgorithmNames(t *testing.T) {
	cases := []struct {
		name     string
		obfs     string
		method   string
		protocol string
	}{
		{"混淆名不在名单", "obfs_not_here", "aes-256-cfb", "origin"},
		{"协议名不在名单", "plain", "aes-256-cfb", "auth_not_here"},
		{"加密名不在名单", "plain", "aes-not-here", "origin"},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			ssrd, err := newDecorateWith(t, item.obfs, item.method, item.protocol, 0, 8388)
			if err == nil {
				t.Fatalf("名单外的名字竟然建好了半成品: %+v", ssrd)
			}
			if ssrd != nil {
				t.Fatalf("出错时必须返回 nil，否则调用方会拿着残缺的装饰器起转发: %+v", ssrd)
			}
		})
	}
}

// 会话身份的唯一来源是端口：多端口下构造完就是监听端口（流量与在线都按它反查），
// 单端口下必须留到 auth 包里那 4 字节解出来才填，不能被端口号顶掉
func TestDecorateIdentityFollowsPortMode(t *testing.T) {
	multi, err := newDecorateWith(t, "plain", "aes-256-cfb", "origin", 0, 8388)
	if err != nil {
		t.Fatalf("多端口装饰器构造失败: %s", err.Error())
	}
	if multi.GetIdentity() != 8388 {
		t.Fatalf("多端口身份 = %d, want 8388", multi.GetIdentity())
	}

	single, err := newDecorateWith(t, "plain", "aes-256-cfb", "origin", 1, 8388)
	if err != nil {
		t.Fatalf("单端口装饰器构造失败: %s", err.Error())
	}
	if single.GetIdentity() != 0 {
		t.Fatalf("单端口在解出 auth 包之前身份应该是 0, got %d", single.GetIdentity())
	}
}

// 32 位目标（linux/386、arm、mips、mipsle 都在发布清单里）不会因为字段插在中间而补对齐，
// 这两个计数器离开结构体首地址就会让 sync/atomic 在运行时 panic unaligned 64-bit atomic operation
func TestAtomicCountersStayAtStructHead(t *testing.T) {
	var decorated ShadowsocksRDecorate

	if off := unsafe.Offsetof(decorated.upload); off != 0 {
		t.Fatalf("upload 偏移 = %d, want 0（必须在结构体首地址）", off)
	}
	if off := unsafe.Offsetof(decorated.download); off != 8 {
		t.Fatalf("download 偏移 = %d, want 8（紧跟 upload，两个都得 8 字节对齐）", off)
	}
}

// 收包缓冲决定大报文会不会在 socket 层被砍尾：SS UDP 报文本身上限 65535，
// 前面还要加 IV/obfs/protocol/AEAD 开销，用 2048 收就会拿到残缺数据
func TestReadFromKeepsWholeDatagram(t *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	port := server.LocalAddr().(*net.UDPAddr).Port

	records := &countingReport{}
	ssrd, err := NewShadowsocksRDecorate(NewRequestWithUDP(server), "plain", "none", "killer",
		"origin", "", "", "127.0.0.1", port, false, 0, nil)
	if err != nil {
		t.Fatalf("UDP 装饰器构造失败: %s", err.Error())
	}
	ssrd.TrafficReport = records

	client, err := net.Dial("udp", server.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	payload := bytes.Repeat([]byte("u"), 8192)
	if _, err = client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err = server.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}

	data, uid, addr, err := ssrd.ReadFrom()
	if err != nil {
		t.Fatalf("ReadFrom 失败: %s", err.Error())
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("整包取出 %d 字节，发出 %d 字节", len(data), len(payload))
	}
	if addr == nil {
		t.Fatal("ReadFrom 没带回对端地址，UDP 就无法回包")
	}
	// 多端口下回给上层的 uid 就是监听端口的 4 字节小端，上层据此继续反查账号
	if got := binaryx.LEBytesToUInt32(uid); int(got) != port {
		t.Fatalf("uid 解出 %d, want 端口 %d", got, port)
	}
	if records.identity != port || records.uploaded != int64(len(payload)) {
		t.Fatalf("上行记账 = (identity %d, %d 字节), want (端口 %d, %d 字节)",
			records.identity, records.uploaded, port, len(payload))
	}
}

// countingReport 记下最后一次上行记账的身份与字节数，用来验「端口即身份」这条耦合。
type countingReport struct {
	identity int
	uploaded int64
}

func (c *countingReport) Upload(identity int, n int64) {
	c.identity = identity
	c.uploaded = n
}

func (c *countingReport) Download(int, int64) {}

// newDecorateWith 用一对内存管道的一端顶替真实连接，造服务端侧装饰器。
func newDecorateWith(t *testing.T, obfsMethod, method, protocol string, single, port int) (*ShadowsocksRDecorate, error) {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	return NewShadowsocksRDecorate(NewRequestWithTCP(server), obfsMethod, method, "killer",
		protocol, "", "", "127.0.0.1", port, false, single, nil)
}
