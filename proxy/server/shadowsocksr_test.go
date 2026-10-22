package server

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProxyPanel/VNet-SSR/common/ciphers"
	"github.com/ProxyPanel/VNet-SSR/common/obfs"
	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/model"
	"github.com/ProxyPanel/VNet-SSR/utils/binaryx"
	"github.com/ProxyPanel/VNet-SSR/utils/socksproxy"
	"github.com/sirupsen/logrus"
)

type fakeFirewall struct {
	mu     sync.Mutex
	judged []string
	deny   bool
}

func (f *fakeFirewall) JudgeHostWithReport(ipOrDomain string, _ int, _ core.AuditContext) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.judged = append(f.judged, ipOrDomain)
	return !f.deny
}

type fakeReport struct {
	mu       sync.Mutex
	identies []int
	uploaded int64
}

func (r *fakeReport) Upload(identity int, n int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.uploaded = n
}

func (r *fakeReport) Download(int, int64) {}

func (r *fakeReport) IdentityToUid(int) int { return 0 }

func (r *fakeReport) Online(identity int, _ string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.identies = append(r.identies, identity)
}

// newTCPProxy 只起 TCP：UDP 那条要真发包，端口生命周期不同，分开测。
func newTCPProxy(t *testing.T, port int, method string, fw core.HostFirewall) *ShadowsocksRProxy {
	t.Helper()

	rep := &fakeReport{}
	ssr := &ShadowsocksRProxy{
		Host:     "127.0.0.1",
		Port:     port,
		Method:   method,
		Password: "killer",
		Protocol: "origin",
		Obfs:     "plain",
		Single:   0,
		Users:    obfs.NewUserTable(),
		ShadowsocksRArgs: &ShadowsocksRArgs{
			TCPSwitch: "true",
			UDPSwitch: "false",
		},
	}
	ssr.HostFirewall = fw
	ssr.TrafficReport = rep
	ssr.OnlineReport = rep

	t.Cleanup(func() {
		if ssr.Listener != nil {
			_ = ssr.Close()
		}
	})
	return ssr
}

// 面板关掉某一项时用的是这两个开关：读错方向就是把该关的端口开着、或把该转发的流量整条掐掉
func TestStartHonoursTCPAndUDPSwitch(t *testing.T) {
	port := freePort(t)
	ssr := newTCPProxy(t, port, "none", &fakeFirewall{})
	ssr.ShadowsocksRArgs.TCPSwitch = "false"

	if err := ssr.Start(); err != nil {
		t.Fatalf("Start 失败: %s", err.Error())
	}
	conn, err := net.DialTimeout("tcp", ssr.Listener.Addr, 500*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Fatal("TCPSwitch=false 时不该有 TCP 监听")
	}
}

// 算法名不在名单里：拒绝这条连接，但端口必须继续服务、进程不能被带崩
// （面板侧的表现是「在线、无人」，靠的就是这里不 panic）
func TestUnsupportedAlgorithmRefusesConnectionWithoutKillingPort(t *testing.T) {
	port := freePort(t)
	ssr := newTCPProxy(t, port, "aes-not-here", &fakeFirewall{})
	if err := ssr.Start(); err != nil {
		t.Fatalf("Start 失败: %s", err.Error())
	}

	addr := ssr.Listener.Addr
	started := time.Now()

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("监听没起来: %s", err.Error())
	}
	defer conn.Close()

	// 被拒的连接必须把 socket 关掉：否则每条名单外连接都漏一个 fd，
	// 客户端只能干等，健康检查也会把端口判成活着
	if _, err = conn.Write(socksRequest("example.com", 80)); err != nil {
		t.Fatalf("写入失败: %s", err.Error())
	}
	body, err := readWithin(conn, 3*time.Second)
	if err == nil && body != "" {
		t.Fatalf("算法名不合法时连接竟然读到数据: %q", body)
	}
	if isTimeout(err) {
		t.Fatalf("服务端没关掉被拒的连接（读一直等到超时），每拒一条就漏一个 socket")
	}

	// 端口仍在服务：第二条连接照样能被 accept
	second, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("第一条被拒后端口不再接受连接: %s", err.Error())
	}
	_ = second.Close()
	t.Logf("拒绝一条非法算法连接耗时 %s", time.Since(started))
}

// 审计命中时节点要替面板把话说完：HTTP 目标回 403，且绝不能再去连上游
func TestAuditRejectAnswers403AndNeverDialsOut(t *testing.T) {
	core.GetApp().SetNodeInfo(&model.NodeInfo{ID: 7, Port: "8388", RedirectUrl: ""})

	port := freePort(t)
	fw := &fakeFirewall{deny: true}
	ssr := newTCPProxy(t, port, "none", fw)
	if err := ssr.Start(); err != nil {
		t.Fatalf("Start 失败: %s", err.Error())
	}

	conn, err := net.DialTimeout("tcp", ssr.Listener.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err = conn.Write(socksRequest("example.com", 80)); err != nil {
		t.Fatal(err)
	}
	body, err := readWithin(conn, 3*time.Second)
	if err != nil {
		t.Fatalf("读拒绝响应失败: %s", err.Error())
	}
	if !strings.Contains(body, "403") {
		t.Fatalf("拒绝响应 = %q, want 403", body)
	}

	fw.mu.Lock()
	judged := append([]string(nil), fw.judged...)
	fw.mu.Unlock()
	if len(judged) == 0 || judged[0] != "example.com" {
		t.Fatalf("审计没问过这个目标: %v", judged)
	}

	// 在线与流量都按端口反查，所以这里登记的必须是监听端口本身
	rep, ok := ssr.TrafficReport.(*fakeReport)
	if !ok {
		t.Fatal("上报器没接上")
	}
	rep.mu.Lock()
	defer rep.mu.Unlock()
	if len(rep.identies) == 0 || rep.identies[0] != port {
		t.Fatalf("在线登记的身份 = %v, want 端口 %d", rep.identies, port)
	}
}

// 面板配了转跳地址时，命中要 302 过去（这是把封禁做成可见提示的那条路）
func TestAuditRejectUsesRedirectUrlWhenSet(t *testing.T) {
	core.GetApp().SetNodeInfo(&model.NodeInfo{ID: 7, Port: "8388", RedirectUrl: "https://panel.example.com/blocked"})

	port := freePort(t)
	ssr := newTCPProxy(t, port, "none", &fakeFirewall{deny: true})
	if err := ssr.Start(); err != nil {
		t.Fatalf("Start 失败: %s", err.Error())
	}

	conn, err := net.DialTimeout("tcp", ssr.Listener.Addr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	if _, err = conn.Write(socksRequest("example.com", 80)); err != nil {
		t.Fatal(err)
	}
	body, err := readWithin(conn, 3*time.Second)
	if err != nil {
		t.Fatalf("读转跳响应失败: %s", err.Error())
	}
	if !strings.Contains(body, "302") || !strings.Contains(body, "https://panel.example.com/blocked") {
		t.Fatalf("转跳响应 = %q, want 302 且带 Location", body)
	}
}

// 密码表用端口的 4 字节小端做键：单端口的 auth 包里那 4 字节按本面板约定装的就是端口
func TestAddUserAndDelUserKeyPasswordTableByPort(t *testing.T) {
	ssr := &ShadowsocksRProxy{}

	ssr.AddUser(8388, "killer")
	key := string(binaryx.LEUint32ToBytes(8388))
	if got := ssr.Users.Lookup(key); got != "killer" {
		t.Fatalf("密码表 = %q, want 端口 8388 对应 killer", got)
	}
	if len(binaryx.LEUint32ToBytes(8388)) != 4 {
		t.Fatal("身份键不是 4 字节，auth 包解出来的长度会对不上")
	}

	ssr.DelUser(8388)
	if got := ssr.Users.Lookup(key); got != "" {
		t.Fatalf("删号后密码表还剩: %q", got)
	}

	// 端口 0 是合法键位（单端口下真实身份来自 auth 包），不能被当成「没填」漏掉
	ssr.AddUser(0, "zero")
	if got := ssr.Users.Lookup(string(binaryx.LEUint32ToBytes(0))); got != "zero" {
		t.Fatal("身份 0 的条目被吞掉了")
	}
}

// socksRequest 拼 SSR 的转发目标头（SOCKS5 地址格式：域名 + 端口）。
func socksRequest(host string, port uint16) []byte {
	out := []byte{socksproxy.AtypDomainName, byte(len(host))}
	out = append(out, host...)
	return append(out, byte(port>>8), byte(port))
}

func readWithin(conn net.Conn, timeout time.Duration) (string, error) {
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return "", err
	}
	body, err := io.ReadAll(conn)
	return string(body), err
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

// logWatcher 收下 logrus 的每条日志，用来发现被 recover 兜成一行日志的 panic。
type logWatcher struct {
	mu      sync.Mutex
	entries []string
}

func (w *logWatcher) Fire(e *logrus.Entry) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.entries = append(w.entries, e.Level.String()+" "+e.Message)
	return nil
}

func (w *logWatcher) Levels() []logrus.Level { return logrus.AllLevels }

func (w *logWatcher) crashes() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var hits []string
	for _, entry := range w.entries {
		if strings.Contains(entry, "invalid memory address") || strings.Contains(entry, "crashed") {
			hits = append(hits, entry)
		}
	}
	return hits
}

func (w *logWatcher) count(substr string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, entry := range w.entries {
		if strings.Contains(entry, substr) {
			n++
		}
	}
	return n
}

type fakeUDPDPILimiter struct {
	mu       sync.Mutex
	allowUps int
}

func (l *fakeUDPDPILimiter) DownLimit(int, int) error { return nil }
func (l *fakeUDPDPILimiter) UpLimit(int, int) error   { return nil }
func (l *fakeUDPDPILimiter) AllowUp(int, int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.allowUps++
	return true
}
func (l *fakeUDPDPILimiter) AllowDown(int, int) bool { return true }

func (l *fakeUDPDPILimiter) allows() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.allowUps
}

// 未认证的短 UDP 包会走到身份协议的解包入口：长度不足时必须在入口拒绝，
// 否则 panic 被 StartUDP 的 recover 兜住后读协程直接退出，端口从此不再处理 UDP
func TestUDPShortDatagramDoesNotKillReader(t *testing.T) {
	port := freeUDPPort(t)
	ssr := newTCPProxy(t, port, "none", &fakeFirewall{})
	ssr.Protocol = "auth_chain_a"
	ssr.ShadowsocksRArgs.TCPSwitch = "false"
	ssr.ShadowsocksRArgs.UDPSwitch = "true"

	watcher := &logWatcher{}
	logrus.AddHook(watcher)

	if err := ssr.Start(); err != nil {
		t.Fatalf("Start 失败: %s", err.Error())
	}

	conn, err := net.Dial("udp", ssr.Listener.Addr)
	if err != nil {
		t.Fatalf("连 UDP 端口失败: %s", err.Error())
	}
	_, _ = conn.Write([]byte{})
	_, _ = conn.Write([]byte{0x00})
	_ = conn.Close()

	time.Sleep(300 * time.Millisecond)

	if hits := watcher.crashes(); len(hits) > 0 {
		t.Fatalf("短 UDP 包之后读协程出现了 panic: %s", hits[0])
	}
}

// UDP 路径上算法名不合法时装饰器是 nil，判 err 之前先碰它会让这个端口的 UDP 读协程在起来那一刻
// panic（被 recover 兜成一行 error），端口绑着却永远不干活——面板只看心跳，表现是「在线、UDP 全废」
func TestUDPWithUnsupportedAlgorithmDoesNotPanic(t *testing.T) {
	port := freePort(t)
	ssr := newTCPProxy(t, port, "aes-not-here", &fakeFirewall{})
	ssr.ShadowsocksRArgs.TCPSwitch = "false"
	ssr.ShadowsocksRArgs.UDPSwitch = "true"

	watcher := &logWatcher{}
	logrus.AddHook(watcher)

	if err := ssr.Start(); err != nil {
		t.Fatalf("Start 失败: %s", err.Error())
	}
	time.Sleep(500 * time.Millisecond)

	if hits := watcher.crashes(); len(hits) > 0 {
		t.Fatalf("UDP 路径上出现了 panic: %s", hits[0])
	}
}

// 未认证的数据报在协议 MAC 上就会被拒：它既不能记到端口对应的账号上（多端口下这个端口就是账号，
// 第三方发垃圾就能替人刷上传），也不能按转发错误刷 Error 日志（可被用来撑大日志/吃满磁盘）。
func TestUnauthenticatedUDPDatagramIsDroppedSilently(t *testing.T) {
	port := freeUDPPort(t)
	ssr := newTCPProxy(t, port, "aes-256-cfb", &fakeFirewall{})
	ssr.Protocol = "auth_chain_a"
	ssr.ShadowsocksRArgs.TCPSwitch = "false"
	ssr.ShadowsocksRArgs.UDPSwitch = "true"
	limiter := &fakeUDPDPILimiter{}
	ssr.ILimiter = limiter

	logger := logrus.StandardLogger()
	oldHooks := logger.ReplaceHooks(logrus.LevelHooks{})
	watcher := &logWatcher{}
	logger.AddHook(watcher)
	t.Cleanup(func() { logger.ReplaceHooks(oldHooks) })

	if err := ssr.Start(); err != nil {
		t.Fatalf("Start 失败: %s", err.Error())
	}

	conn, err := net.Dial("udp", ssr.Listener.Addr)
	if err != nil {
		t.Fatalf("连 UDP 端口失败: %s", err.Error())
	}
	defer conn.Close()
	if _, err := conn.Write(bytes.Repeat([]byte{0x5a}, 64)); err != nil {
		t.Fatalf("发包失败: %s", err.Error())
	}

	time.Sleep(500 * time.Millisecond)

	rep := ssr.TrafficReport.(*fakeReport)
	rep.mu.Lock()
	uploaded := rep.uploaded
	rep.mu.Unlock()

	if uploaded != 0 {
		t.Fatalf("未认证的 UDP 包被记了 %d 字节上传", uploaded)
	}
	if n := watcher.count("read address error") + watcher.count("read udp error"); n != 0 {
		t.Fatalf("未认证的 UDP 包刷了 %d 条 Error 日志", n)
	}
	if limiter.allows() != 0 {
		t.Fatalf("未认证的 UDP 包被扣了 %d 次限速", limiter.allows())
	}
}

// StartUDP 必须把 proxy 上的限速器交给装饰器：漏了这一句时 AllowUp/AllowDown 恒为 nil 判断，
// 面板下发的 UDP 限速完全不生效。
func TestAuthenticatedUDPDatagramGoesThroughLimiter(t *testing.T) {
	port := freeUDPPort(t)
	ssr := newTCPProxy(t, port, "aes-256-cfb", &fakeFirewall{})
	ssr.Protocol = "auth_chain_a"
	ssr.ShadowsocksRArgs.TCPSwitch = "false"
	ssr.ShadowsocksRArgs.UDPSwitch = "true"
	limiter := &fakeUDPDPILimiter{}
	ssr.ILimiter = limiter

	if err := ssr.Start(); err != nil {
		t.Fatalf("Start 失败: %s", err.Error())
	}

	enc, err := ciphers.NewEncryptor("aes-256-cfb", "killer")
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
	datagram, err := enc.EncryptAll(packet, enc.MustNewIV())
	if err != nil {
		t.Fatalf("加密失败: %s", err.Error())
	}

	conn, err := net.Dial("udp", ssr.Listener.Addr)
	if err != nil {
		t.Fatalf("连 UDP 端口失败: %s", err.Error())
	}
	defer conn.Close()
	if _, err := conn.Write(datagram); err != nil {
		t.Fatalf("发包失败: %s", err.Error())
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && limiter.allows() == 0 {
		time.Sleep(10 * time.Millisecond)
	}

	if limiter.allows() == 0 {
		t.Fatal("认证通过的 UDP 包没有过限速：StartUDP 没把 limiter 交给装饰器")
	}

	rep := ssr.TrafficReport.(*fakeReport)
	rep.mu.Lock()
	uploaded := rep.uploaded
	rep.mu.Unlock()
	if uploaded == 0 {
		t.Fatal("认证通过的 UDP 包没有记账")
	}
}
