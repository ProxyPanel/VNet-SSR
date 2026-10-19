package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ProxyPanel/VNet-SSR/api/client"
	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/model"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
	"github.com/go-resty/resty/v2"
)

const testPushSecret = "test-push-secret"

func newPushRouter(t *testing.T, secret string) *httptest.Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	SetSecret(secret)
	server := httptest.NewServer(InitRouter())
	t.Cleanup(func() {
		server.Close()
		SetSecret("")
	})
	return server
}

func postTo(t *testing.T, url, secret, body string) (int, string) {
	t.Helper()
	resp, err := resty.New().SetTimeout(30 * time.Second).R().
		SetHeader("secret", secret).
		SetHeader("Content-Type", "application/json").
		SetBody(body).
		Post(url)
	if err != nil {
		t.Fatalf("请求 %s 失败: %s", url, err.Error())
	}
	return resp.StatusCode(), string(resp.Body())
}

func getFrom(t *testing.T, url, secret string) (int, string) {
	t.Helper()
	resp, err := resty.New().SetTimeout(30 * time.Second).R().
		SetHeader("secret", secret).
		Get(url)
	if err != nil {
		t.Fatalf("请求 %s 失败: %s", url, err.Error())
	}
	return resp.StatusCode(), string(resp.Body())
}

// secret 为空时期望值是 ""，不带 secret 头的请求拿 "" 与之相等会直接放行，
// 等于把「改用户表、重载整节点」开放给任何能连上 push_port 的人
func TestPushRejectsWhenSecretEmpty(t *testing.T) {
	panel := newPushRouter(t, "")

	_, body := getFrom(t, panel.URL+"/api/user/list", "")
	if !strings.Contains(body, ErrEmptySecret.Error()) {
		t.Fatalf("空 secret 下 %q, want 拒绝并说明原因", body)
	}

	if status := gjson.Get(body, "success").String(); status != "false" {
		t.Fatalf("空 secret 的响应 success = %q, want false", status)
	}
}

func TestPushRejectsWrongSecret(t *testing.T) {
	panel := newPushRouter(t, testPushSecret)

	_, body := getFrom(t, panel.URL+"/api/user/list", "not-the-secret")
	if gjson.Get(body, "success").String() != "false" {
		t.Fatalf("错 secret 被放行: %s", body)
	}

	// 正确的那一把要能过去，否则上面那条判据是恒真
	status, _ := getFrom(t, panel.URL+"/api/user/list", testPushSecret)
	if status != http.StatusOK {
		t.Fatalf("正确 secret 的状态 = %d, want 200", status)
	}
}

// 空 secret 时连监听都不该起：只靠中间件挡，端口上还挂着个可被探测的服务
func TestStartServerRefusesToListenWithoutSecret(t *testing.T) {
	port := freePort(t)

	StartServer(port, "")
	if conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 300*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatalf("空 secret 仍在 :%d 上监听了", port)
	}

	// 给了 secret 就该正常起来（同端口，证明上一条不是端口本身的问题）
	StartServer(port, testPushSecret)
	if !waitForListen(port, 2*time.Second) {
		t.Fatalf("带 secret 时 :%d 没有监听", port)
	}
	StopServer()
}

func TestNodeReloadRejectsEmptySecret(t *testing.T) {
	core.GetApp().SetNodeInfo(&model.NodeInfo{ID: 7, Port: "8388", Secret: testPushSecret, PushPort: 30108})
	panel := newPushRouter(t, testPushSecret)

	// secret 判据排在面板调用之前：客户端拉一次要按 pullAttempts 退避重试（约 10 秒），
	// 所以这一条如果秒回，就说明它根本没去打面板
	started := time.Now()
	_, body := postTo(t, panel.URL+"/api/v2/node/reload", testPushSecret, `{"id":7,"port":"9000","secret":""}`)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("空 secret 的重载花了 %s，说明它先去打面板了", elapsed)
	}
	if !strings.Contains(body, ErrEmptySecret.Error()) {
		t.Fatalf("空 secret 的重载没有回绝: %s", body)
	}
	if core.GetApp().NodeInfo().Port != "8388" {
		t.Fatalf("重载被拒后配置仍被改写: %+v", core.GetApp().NodeInfo())
	}
}

// 单端口只有一个监听端口，账号全靠鉴权包头那 4 字节区分：配上不带身份的协议时
// 节点认不出谁在连，流量、在线与限速全部落空，必须在落地前拒掉
func TestValidateNodeInfoRejectsSinglePortWithoutIdentity(t *testing.T) {
	if err := ValidateNodeInfo(&model.NodeInfo{Secret: testPushSecret, Single: 1, Protocol: "auth_chain_a"}); err != nil {
		t.Fatalf("单端口 + auth_chain_a 不该被拒: %v", err)
	}
	// 多端口不受这条判据约束：账号由各自的监听端口区分
	if err := ValidateNodeInfo(&model.NodeInfo{Secret: testPushSecret, Single: 0, Protocol: "origin"}); err != nil {
		t.Fatalf("多端口 + origin 不该被拒: %v", err)
	}

	for _, protocol := range []string{"origin", "plain", "http_simple", "http_post", "tls1.2_ticket_auth", "auth_sha1_v4", ""} {
		err := ValidateNodeInfo(&model.NodeInfo{Secret: testPushSecret, Single: 1, Protocol: protocol})
		if err == nil {
			t.Fatalf("单端口 + %q 被接受了，节点将无法归属任何流量", protocol)
		}
	}

	// secret 那条判据不能被这条改动吃掉
	if err := ValidateNodeInfo(&model.NodeInfo{Single: 1, Protocol: "auth_chain_a"}); err != ErrEmptySecret {
		t.Fatalf("空 secret 的判据变了: %v", err)
	}
}

// 分组模式带不了 UDP 数据报：每个包都是自带 IV 的一次性加解密，不足一块的尾巴没有下一批可等。
// TCP 字节流按块边界走是可以的，所以只拒 UDP 那一半
func TestValidateNodeInfoRejectsBlockCipherWithUDP(t *testing.T) {
	if err := ValidateNodeInfo(&model.NodeInfo{Secret: testPushSecret, Method: "aes-128-cbc", IsUDP: 1}); err == nil {
		t.Fatal("aes-128-cbc + is_udp=1 被接受了，数据报会静默截尾")
	}
	if err := ValidateNodeInfo(&model.NodeInfo{Secret: testPushSecret, Method: "aes-128-cbc"}); err != nil {
		t.Fatalf("走 TCP 的 aes-128-cbc 不该被拒: %v", err)
	}
	for _, method := range []string{"aes-256-cfb", "chacha20-ietf-poly1305", "none"} {
		if err := ValidateNodeInfo(&model.NodeInfo{Secret: testPushSecret, Method: method, IsUDP: 1}); err != nil {
			t.Fatalf("%s + UDP 不该被拒: %v", method, err)
		}
	}
}

// 单端口配不带身份的协议时，重载要秒回拒绝并且不改写在跑的配置：
// 判据排在打面板之前，面板可达与否都不该被这条坏配置波及
func TestNodeReloadRejectsSinglePortWithoutIdentity(t *testing.T) {
	core.GetApp().SetNodeInfo(&model.NodeInfo{ID: 7, Port: "8388", Secret: testPushSecret, PushPort: 30108})
	panel := newPushRouter(t, testPushSecret)

	started := time.Now()
	_, body := postTo(t, panel.URL+"/api/v2/node/reload", testPushSecret,
		`{"id":7,"port":"8388","secret":"`+testPushSecret+`","single":1,"protocol":"origin","push_port":30108}`)
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("单端口判据花了 %s，说明它先去打面板了", elapsed)
	}
	if gjson.Get(body, "success").String() != "false" {
		t.Fatalf("单端口 + origin 的重载被接受了: %s", body)
	}
	if core.GetApp().NodeInfo().Protocol != "" {
		t.Fatalf("重载被拒后配置仍被改写: %+v", core.GetApp().NodeInfo())
	}
}

// 面板此刻取不到用户表时，重载必须原样保留在跑的服务：
// 先把新集合取到手才改配置，否则端口会被打空、在线全断
func TestNodeReloadKeepsRunningConfigWhenPanelUnreachable(t *testing.T) {
	core.GetApp().SetNodeInfo(&model.NodeInfo{ID: 7, Port: "8388", Method: "aes-256-cfb", Secret: testPushSecret, PushPort: 30108})
	prevHost, prevID, prevKey := client.Host, core.GetApp().NodeId(), core.GetApp().Key()
	t.Cleanup(func() {
		client.Host = prevHost
		core.GetApp().SetNodeId(prevID)
		core.GetApp().SetKey(prevKey)
	})

	// 9 号端口（discard）本机无人监听，连接立刻被拒；客户端按 pullAttempts 退避重试后才回错
	client.Host = "http://127.0.0.1:9/api/ssr/v1"
	core.GetApp().SetNodeId(7)
	core.GetApp().SetKey("node-secret")

	panel := newPushRouter(t, testPushSecret)
	_, body := postTo(t, panel.URL+"/api/v2/node/reload", testPushSecret,
		`{"id":7,"port":"9000","method":"chacha20","secret":"`+testPushSecret+`","push_port":30108}`)

	if gjson.Get(body, "success").String() != "false" {
		t.Fatalf("面板取不到用户表时重载竟然回了成功: %s", body)
	}
	if kept := core.GetApp().NodeInfo(); kept.Port != "8388" || kept.Method != "aes-256-cfb" {
		t.Fatalf("重载失败后配置被换成新值: %+v", kept)
	}
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

func waitForListen(port int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}
