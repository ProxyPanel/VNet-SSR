package server

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/api/client"
	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/common/obfs"
	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/model"
	"github.com/ProxyPanel/VNet-SSR/service"
	"github.com/ProxyPanel/VNet-SSR/utils/goroutine"
	"github.com/ProxyPanel/VNet-SSR/utils/langx"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"io/ioutil"
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
		body, _ := ioutil.ReadAll(c.Request.Body)
		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(body))
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
	}
	return r
}

func UsersAdd(c *gin.Context) {
	var users []*model.UserInfo
	if err := c.BindJSON(&users); err != nil {
		fail(c, err)
		return
	}

	if err := service.GetSSRManager().ApplyUsers(users); err != nil {
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

	if err := service.GetSSRManager().AddUser(&user); err != nil {
		fail(c, err)
		return
	}
	success(c)
}

func UserDel(c *gin.Context) {
	if err := service.GetSSRManager().DelUser(langx.FirstResult(strconv.Atoi, c.Param("uid")).(int)); err != nil {
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
	if err := service.GetSSRManager().EditUser(&user); err != nil {
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
	// 带着空 secret 落配置，重启后 push 服务就不再起来（StartServer 拒绝监听），节点会失联
	if nodeInfo.Secret == "" {
		fail(c, ErrEmptySecret)
		return
	}
	// 先把新集合取到手再改配置：面板此刻不可达时保持原样，不把已经在跑的服务打空
	users, err := client.GetUserList()
	if err != nil {
		fail(c, errors.Wrap(err, "get user list failed, current services kept"))
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

func successWithData(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, gin.H{"success": "true", "content": "sucess", "data": data})
}
