package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/api/client"
	"github.com/ProxyPanel/VNet-SSR/common/ciphers/block"
	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/common/obfs"
	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/model"
	"github.com/ProxyPanel/VNet-SSR/service"
	"github.com/ProxyPanel/VNet-SSR/utils/goroutine"
	"github.com/ProxyPanel/VNet-SSR/utils/langx"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	START = iota
	CLOSE = iota
)

var (
	// 中间件在多个 gin 协程里读，StartServer/NodeReload 在别的协程写——必须原子存取
	pushSecret      atomic.Value // string
	httpServer      *http.Server
	httpServerMutex sync.Locker = new(sync.Mutex)
	httpServerChan  chan int    = make(chan int, 2)
)

func init() {
	go goroutine.Protect(func() {
		for {
			sig := <-httpServerChan
			switch sig {
			case START:
				StartServer(core.GetApp().NodeInfo().PushPort, core.GetApp().NodeInfo().Secret)
			case CLOSE:
				StopServer()
			}

		}
	})
}

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
	if nodeInfo.Single == 1 && !obfs.CarriesIdentity(nodeInfo.Protocol) {
		return fmt.Errorf("single port mode needs a protocol that carries the account identity, %q carries none; usable: %s", nodeInfo.Protocol, strings.Join(obfs.IdentityBearingNames(), ", "))
	}
	// 分组模式没有字节粒度的语义：TCP 字节流可以按块边界走（尾巴等下一批），但每个 UDP 数据报
	// 都是自带 IV 的一次性加解密，没有下一批可等，不足一块的尾巴只能丢。
	// 与其让数据报静默截尾，不如把这种组合拒在落地之前
	if nodeInfo.IsUDP == 1 && block.GetBlockCipher(nodeInfo.Method) != nil {
		return fmt.Errorf("%s is a block cipher and cannot carry UDP datagrams; pick a stream cipher or set is_udp to 0", nodeInfo.Method)
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

func detailLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		body, _ := io.ReadAll(c.Request.Body)
		c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
		// body 里有 passwd 与 secret，默认级别只留方法+路径
		log.Info("%s,%s", c.Request.Method, c.Request.RequestURI)
		log.Debug("%s,%s,%s", c.Request.Method, c.Request.RequestURI, body)
		c.Next()
	}
}

func StartServer(port int, s string) {
	httpServerMutex.Lock()
	defer httpServerMutex.Unlock()
	if httpServer != nil {
		log.Error("http server is not close")
		return
	}
	if s == "" {
		// 监听 :push_port 且无凭据 = 任何人可改用户表、重载整节点配置
		log.Error("%v, push server on port %v is not started", ErrEmptySecret, port)
		return
	}
	addr := fmt.Sprintf(":%v", port)
	SetSecret(s)
	log.Info("start server on %s", addr)
	r := InitRouter()
	httpServer = &http.Server{
		Addr:    addr,
		Handler: r,
	}

	go goroutine.Protect(func() {
		if err := httpServer.ListenAndServe(); err != nil {
			if strings.Contains(err.Error(), " Server closed") {
				return
			}
			panic(err)
		}
	})
}

func StopServer() {
	httpServerMutex.Lock()
	defer httpServerMutex.Unlock()
	if err := httpServer.Shutdown(context.Background()); err != nil {
		log.Err(err)
	}
	httpServer = nil
	return
}

func InitRouter() *gin.Engine {
	r := gin.Default()
	r.Use(detailLog())
	r.Use(secretCheck())
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

	if err := service.GetSSRManager().ApplyUsers(service.SourcePush, users); err != nil {
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

	if err := service.GetSSRManager().DelUsers(uids); err != nil {
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
	if err := service.GetSSRManager().ApplyUsers(service.SourcePush, []*model.UserInfo{&user}); err != nil {
		fail(c, err)
		return
	}
	success(c)
}

func UserDel(c *gin.Context) {
	uid := langx.FirstResult(strconv.Atoi, c.Param("uid")).(int)
	client.MarkUserListStale()

	if err := service.GetSSRManager().DelUser(uid); err != nil {
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

	if err := service.GetSSRManager().ApplyUsers(service.SourcePush, []*model.UserInfo{&user}); err != nil {
		fail(c, err)
		return
	}
	success(c)

}

func UserList(c *gin.Context) {
	c.JSON(http.StatusOK, service.GetSSRManager().GetUserList())
}

func NodeReload(c *gin.Context) {
	var nodeInfo model.NodeInfo
	if err := c.ShouldBind(&nodeInfo); err != nil {
		fail(c, err)
		return
	}
	// 带着空 secret 或不携带账号身份的协议落配置，节点会失联或全部流量无法归属
	if err := ValidateNodeInfo(&nodeInfo); err != nil {
		fail(c, err)
		return
	}
	// 先把新集合取到手再改配置：面板此刻不可达时保持原样，不把已经在跑的服务打空
	users, err := client.GetUserList()
	if err != nil {
		fail(c, fmt.Errorf("%s: %w", "get user list failed, current services kept", err))
		return
	}
	core.GetApp().SetNodeInfo(&nodeInfo)
	core.GetApp().SetObfsProtocolService(obfs.NewObfsAuthChainData(nodeInfo.Protocol))
	if nodeInfo.ClientLimit != 0 {
		log.Info("set client limit with %v", nodeInfo.ClientLimit)
		core.GetApp().GetObfsProtocolService().SetMaxClient(nodeInfo.ClientLimit)
	} else {
		log.Info("ignore client limit, because client_limit is zero, use default limit is 64")
	}
	if err := service.Reload(users); err != nil {
		fail(c, err)
		return
	}
	success(c)
	httpServerChan <- CLOSE
	httpServerChan <- START
}

func fail(c *gin.Context, err error) {
	c.JSON(http.StatusOK, gin.H{"success": "false", "content": err.Error()})
}

func success(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"success": "true", "content": "sucess"})
}
