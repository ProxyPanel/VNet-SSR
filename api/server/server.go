package server

import (
	"bytes"
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/rc452860/vnet/common/log"
	"github.com/rc452860/vnet/common/obfs"
	"github.com/rc452860/vnet/core"
	"github.com/rc452860/vnet/model"
	"github.com/rc452860/vnet/service"
	"github.com/rc452860/vnet/utils/goroutine"
	"github.com/rc452860/vnet/utils/langx"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"sync"
)

const (
	START = iota
	CLOSE = iota
)

var (
	secret          string
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
	secret = s
}

func secretCheck() gin.HandlerFunc {
	return func(c *gin.Context) {
		s := c.GetHeader("secret")
		if s == secret {
			c.Next()
		} else {
			c.Abort()
			fail(c, errors.New("secret check error"))
		}
	}
}

func detailLog() gin.HandlerFunc {
	return func(c *gin.Context) {
		body, _ := ioutil.ReadAll(c.Request.Body)
		c.Request.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		log.Info("%s,%s,%s", c.Request.Method, c.Request.RequestURI, body)
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
	addr := fmt.Sprintf(":%v", port)
	SetSecret(s)
	log.Info("start server on %s secret %s", addr, s)
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

	if err := service.GetSSRManager().AddUsers(users); err != nil {
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
	core.GetApp().SetNodeInfo(&nodeInfo)
	core.GetApp().SetObfsProtocolService(obfs.NewObfsAuthChainData(nodeInfo.Protocol))
	if nodeInfo.ClientLimit != 0 {
		log.Info("set client limit with %v", nodeInfo.ClientLimit)
		core.GetApp().GetObfsProtocolService().SetMaxClient(nodeInfo.ClientLimit)
	} else {
		log.Info("ignore client limit, because client_limit is zero, use default limit is 64")
	}
	if err := service.Reload(); err != nil {
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
