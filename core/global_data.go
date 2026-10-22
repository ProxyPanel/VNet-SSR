package core

import (
	"sync/atomic"

	"github.com/ProxyPanel/VNet-SSR/model"
)

var (
	app = NewApp()
)

func NewApp() *App {
	return new(App)
}

func GetApp() *App {
	return app
}

type App struct {
	// 重载协程写、每条连接读：指针与 interface 都必须原子存取
	nodeInfo            atomic.Pointer[model.NodeInfo]
	nodeId              int
	apiHost             string
	key                 string
	host                string
	obfsProtocolService atomic.Value // obfsServiceHolder
}

type obfsServiceHolder struct {
	service ObfsProtocolService
}

func (a *App) Init() error {
	return nil
}

func (a *App) Host() string {
	return a.host
}

func (a *App) SetHost(host string) {
	a.host = host
}

func (a *App) Key() string {
	return a.key
}

func (a *App) SetKey(key string) {
	a.key = key
}

func (a *App) SetNodeInfo(nodeInfo *model.NodeInfo) {
	a.nodeInfo.Store(nodeInfo)
}

func (a *App) NodeInfo() *model.NodeInfo {
	return a.nodeInfo.Load()
}

func (a *App) NodeId() int {
	return a.nodeId
}

func (a *App) SetNodeId(nodeId int) {
	a.nodeId = nodeId
}

func (a *App) ApiHost() string {
	return a.apiHost
}

func (a *App) SetApiHost(apiHost string) {
	a.apiHost = apiHost
}

func (a *App) SetObfsProtocolService(obfsProtocolService ObfsProtocolService) {
	a.obfsProtocolService.Store(obfsServiceHolder{service: obfsProtocolService})
}

func (a *App) GetObfsProtocolService() ObfsProtocolService {
	holder, _ := a.obfsProtocolService.Load().(obfsServiceHolder)
	return holder.service
}
