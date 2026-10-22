package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ProxyPanel/VNet-SSR/api/client"
	"github.com/ProxyPanel/VNet-SSR/common/ciphers/block"
	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/common/obfs"
	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/model"
	"github.com/ProxyPanel/VNet-SSR/service"
	"github.com/ProxyPanel/VNet-SSR/utils/langx"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

const (
	// push 载荷最大 32MiB：整批下发可能带全量用户表，但没有理由接受无界请求体
	maxPushBody = 32 << 20
	// 调试日志只留请求体前缀，完整用户表不该整份进内存再进日志
	maxLoggedBody = 64 << 10
)

var (
	// 中间件在多个 gin 协程里读，StartServer/NodeReload 在别的协程写——必须原子存取
	pushSecret      atomic.Value // string
	httpServer      *http.Server
	httpServerMutex sync.Mutex
	// runningPushPort 是实际在监听的那个端口，不是 NodeInfo 里的期望值：
	// 端口切换的 goroutine 还没落地时，再次重载要以真实监听为准
	runningPushPort int
	// reloadMu 串行化整节点重载；pushRestartMu 串行化监听器切换
	reloadMu      sync.Mutex
	pushRestartMu sync.Mutex
	// pushReloadSeq 让最后一次重载赢：前一次还没落地的监听器切换会被作废并关闭
	pushReloadSeq atomic.Uint64
)

func SetSecret(s string) {
	pushSecret.Store(s)
}

func loadSecret() string {
	if s, ok := pushSecret.Load().(string); ok {
		return s
	}
	return ""
}

// ErrEmptySecret 面板没给 secret 时的判据：空 secret 会让「不带 header」的请求恒等于服务端期望值
var ErrEmptySecret = errors.New("node secret is empty, refusing to accept push requests")

// ValidateNodeInfo 是节点配置落地的判据，启动拉取与面板推送两条路都过它。
// 单端口只有一个监听端口，账号全靠鉴权包头那 4 字节区分：配上不携带身份的协议
// （origin/plain/http_*/tls_*/auth_sha1_v4）时节点认不出谁在连，流量、在线与限速会全部落空，
// 所以直接拒绝落地，而不是带着一个不可能归属成功的配置跑下去
func ValidateNodeInfo(nodeInfo *model.NodeInfo) error {
	if nodeInfo.Secret == "" {
		return ErrEmptySecret
	}
	if nodeInfo.PushPort <= 0 || nodeInfo.PushPort > 65535 {
		return fmt.Errorf("push port %d is invalid", nodeInfo.PushPort)
	}
	if nodeInfo.Single == 1 && !obfs.CarriesIdentity(nodeInfo.Protocol) {
		return fmt.Errorf("single port mode needs a protocol that carries the account identity, %q carries none; usable: %s", nodeInfo.Protocol, strings.Join(obfs.IdentityBearingNames(), ", "))
	}
	if nodeInfo.Single == 1 {
		if err := validatePortList(nodeInfo.Port); err != nil {
			return err
		}
	}
	// 分组模式没有字节粒度的语义：TCP 字节流可以按块边界走（尾巴等下一批），但每个 UDP 数据报
	// 都是自带 IV 的一次性加解密，没有下一批可等，不足一块的尾巴只能丢。
	// 与其让数据报静默截尾，不如把这种组合拒在落地之前
	if nodeInfo.IsUDP == 1 && block.GetBlockCipher(nodeInfo.Method) != nil {
		return fmt.Errorf("%s is a block cipher and cannot carry UDP datagrams; pick a stream cipher or set is_udp to 0", nodeInfo.Method)
	}
	return nil
}

func validatePortList(raw string) error {
	for _, item := range strings.Split(raw, ",") {
		port, err := strconv.Atoi(strings.TrimSpace(item))
		if err != nil || port <= 0 || port > 65535 {
			return fmt.Errorf("invalid port list %q", raw)
		}
	}
	return nil
}

func secretCheck() gin.HandlerFunc {
	return func(c *gin.Context) {
		expected := loadSecret()
		// 空 secret 一律拒：否则不带 secret 头的请求拿到 ""，比对 "" 直接放行
		if expected == "" {
			c.Abort()
			fail(c, ErrEmptySecret)
			return
		}
		if subtle.ConstantTimeCompare([]byte(c.GetHeader("secret")), []byte(expected)) != 1 {
			c.Abort()
			fail(c, errors.New("secret check error"))
			return
		}
		c.Next()
	}
}

// limitBody 必须在任何读取请求体的处理之前：未认证请求不该先分配一整份 body
func limitBody() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxPushBody)
		c.Next()
	}
}

func detailLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		// body 里有 passwd 与 secret，默认级别只留方法+路径
		log.Info("%s,%s", c.Request.Method, c.Request.RequestURI)
		if logrus.IsLevelEnabled(logrus.DebugLevel) {
			head, _ := io.ReadAll(io.LimitReader(c.Request.Body, maxLoggedBody))
			c.Request.Body = io.NopCloser(io.MultiReader(bytes.NewReader(head), c.Request.Body))
			log.Debug("%s,%s,%s", c.Request.Method, c.Request.RequestURI, head)
		}
		c.Next()
	}
}

// StartServer 同步完成 bind 再返回：端口被占用时调用方必须能拿到错误，而不是只在后台日志里看到
func StartServer(port int, s string) error {
	if s == "" {
		// 监听 :push_port 且无凭据 = 任何人可改用户表、重载整节点配置
		return ErrEmptySecret
	}
	if port <= 0 || port > 65535 {
		return fmt.Errorf("push port %d is invalid", port)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("%s: %w", "listen push port", err)
	}
	if err := servePush(ln, s, port); err != nil {
		_ = ln.Close()
		return err
	}
	return nil
}

func servePush(ln net.Listener, secret string, port int) error {
	httpServerMutex.Lock()
	defer httpServerMutex.Unlock()
	if httpServer != nil {
		return errors.New("http server is not close")
	}
	SetSecret(secret)
	log.Info("start server on %s", ln.Addr())
	srv := &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           InitRouter(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		// NodeReload 可能先按 3 次退避拉用户表（约 25 秒）再重建监听
		WriteTimeout:   60 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	httpServer = srv
	runningPushPort = port
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logrus.Error(err)
		}
	}()
	return nil
}

// StopServer 幂等：并发的重载或退出路径重复调用不能 nil 解引用
func StopServer() error {
	httpServerMutex.Lock()
	srv := httpServer
	httpServer = nil
	runningPushPort = 0
	httpServerMutex.Unlock()
	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		_ = srv.Close()
		return err
	}
	return nil
}

func currentPushPort() int {
	httpServerMutex.Lock()
	port := runningPushPort
	httpServerMutex.Unlock()
	return port
}

// restartPushListener 换端口：先停旧监听再服务新监听；被后续重载作废的那一次直接关闭预绑的 listener
func restartPushListener(seq uint64, ln net.Listener, secret string, port int) {
	pushRestartMu.Lock()
	defer pushRestartMu.Unlock()

	if seq != pushReloadSeq.Load() {
		_ = ln.Close()
		return
	}
	if err := StopServer(); err != nil {
		log.Err(err)
	}
	if err := servePush(ln, secret, port); err != nil {
		log.Err(err)
		_ = ln.Close()
	}
}

func InitRouter() *gin.Engine {
	r := gin.Default()
	// 鉴权必须排在读取请求体之前：先读 body 等于把未认证请求的内存分配交给对端
	r.Use(secretCheck())
	r.Use(limitBody())
	r.Use(detailLog())
	r1 := r.Group("/api")
	{
		r1.POST("/user/add", UserAdd)
		r1.POST("/user/del/:uid", UserDel)
		r1.POST("/user/edit", UserEdit)
		r1.GET("/user/list", UserList)
	}
	r2 := r.Group("/api/v2")
	{
		r2.POST("/user/del/list", UsersDel)
		r2.POST("/user/add/list", UsersAdd)
		r2.POST("/node/reload", NodeReload)
		r2.POST("/rule/reload", RuleReload)
	}
	return r
}

// RuleReload 只重拉审计规则，不重建监听器、不断在线连接；拉取失败保留旧规则集并回错误，
// 面板队列按作业的 $tries 重试
func RuleReload(c *gin.Context) {
	if err := service.GetRuleService().LoadFromApi(); err != nil {
		fail(c, fmt.Errorf("%s: %w", "reload rule failed, old rule set kept", err))
		return
	}
	success(c)
}

func UsersAdd(c *gin.Context) {
	var users []*model.UserInfo
	if err := c.BindJSON(&users); err != nil {
		fail(c, err)
		return
	}

	client.MarkUserListStale()

	if err := service.GetSSRManager().ApplyUsersFromPush(users); err != nil {
		fail(c, err)
		return
	}

	success(c)
}

func UsersDel(c *gin.Context) {
	var uids []int
	if err := c.ShouldBind(&uids); err != nil {
		fail(c, err)
		return
	}

	client.MarkUserListStale()

	if err := service.GetSSRManager().DelUsersFromPush(uids); err != nil {
		fail(c, err)
		return
	}

	success(c)
}

func UserAdd(c *gin.Context) {
	var user model.UserInfo
	if err := c.ShouldBind(&user); err != nil {
		fail(c, err)
		return
	}

	client.MarkUserListStale()

	// 与批量端点同一条落地路径：按 uid 落目标状态，内容一致时不动表也不记日志
	if err := service.GetSSRManager().ApplyUsersFromPush([]*model.UserInfo{&user}); err != nil {
		fail(c, err)
		return
	}
	success(c)
}

func UserDel(c *gin.Context) {
	uid := langx.FirstResult(strconv.Atoi, c.Param("uid")).(int)
	client.MarkUserListStale()

	if err := service.GetSSRManager().DelUserFromPush(uid); err != nil {
		fail(c, err)
		return
	}
	success(c)
}

func UserEdit(c *gin.Context) {
	var user model.UserInfo
	if err := c.ShouldBind(&user); err != nil {
		fail(c, err)
		return
	}

	client.MarkUserListStale()

	if err := service.GetSSRManager().ApplyUsersFromPush([]*model.UserInfo{&user}); err != nil {
		fail(c, err)
		return
	}
	success(c)

}

func UserList(c *gin.Context) {
	c.JSON(http.StatusOK, service.GetSSRManager().GetUserList())
}

func NodeReload(c *gin.Context) {
	// 同一时刻只处理一次重载：并发的两次重启会互相拆掉对方的监听器
	reloadMu.Lock()
	defer reloadMu.Unlock()

	var nodeInfo model.NodeInfo
	if err := c.ShouldBind(&nodeInfo); err != nil {
		fail(c, err)
		return
	}
	// 带着空 secret、非法端口或不携带账号身份的协议落配置，节点会失联或全部流量无法归属
	if err := ValidateNodeInfo(&nodeInfo); err != nil {
		fail(c, err)
		return
	}
	// 先把新集合取到手再改配置：面板此刻不可达时保持原样，不把已经在跑的服务打空。
	// 取数最长约 25 秒，期间落地的推送会让这份快照过期，重建前按取数前记的代次再判一次
	gen := service.GetSSRManager().UsersGeneration()
	users, err := client.GetUserList()
	if err != nil {
		fail(c, fmt.Errorf("%s: %w", "get user list failed, current services kept", err))
		return
	}

	// 端口没变就只换 secret，不重建监听；端口变了先 bind 新监听，bind 失败时不改任何配置
	oldPushPort := currentPushPort()
	restartNeeded := nodeInfo.PushPort != oldPushPort
	var newListener net.Listener
	if restartNeeded {
		newListener, err = net.Listen("tcp", fmt.Sprintf(":%d", nodeInfo.PushPort))
		if err != nil {
			fail(c, fmt.Errorf("%s: %w", "listen new push port", err))
			return
		}
	}

	oldObfsService := core.GetApp().GetObfsProtocolService()
	// 从这里开始这次重载一定会落配置（即使随后 service.Reload 失败，NodeInfo 也已切换）：
	// 先作废还没落地的旧监听切换，避免它在下面耗时较长的 Reload 期间把当前 push server 停掉
	seq := pushReloadSeq.Add(1)

	core.GetApp().SetNodeInfo(&nodeInfo)
	obfsService := obfs.NewObfsAuthChainData(nodeInfo.Protocol)
	core.GetApp().SetObfsProtocolService(obfsService)
	if oldObfsService != nil {
		// 旧单例的桶回收协程与每个账号的 janitor 不能跟着连接一直留着
		oldObfsService.Close()
	}
	if nodeInfo.ClientLimit != 0 {
		log.Info("set client limit with %v", nodeInfo.ClientLimit)
		obfsService.SetMaxClient(nodeInfo.ClientLimit)
	} else {
		log.Info("ignore client limit, because client_limit is zero, use default limit is 64")
	}

	reloadErr := service.Reload(users, gen)
	if reloadErr != nil {
		client.MarkUserListStale()
	}

	// 配置已经落地（可能只落地了一部分）：push 监听必须跟到新的端口与 secret，
	// 否则面板会对着旧端口或旧凭据推送，节点再也修不回来
	SetSecret(nodeInfo.Secret)
	if reloadErr != nil {
		fail(c, reloadErr)
	} else {
		success(c)
	}
	if restartNeeded {
		go restartPushListener(seq, newListener, nodeInfo.Secret, nodeInfo.PushPort)
	}
}

func fail(c *gin.Context, err error) {
	c.JSON(http.StatusOK, gin.H{"success": "false", "content": err.Error()})
}

func success(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": "true", "content": "sucess"})
}
