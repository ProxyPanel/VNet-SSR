package core

import (
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
	nodeInfo            *model.NodeInfo
	nodeId              int
	apiHost             string
	key                 string
	host                string
	obfsProtocolService ObfsProtocolService
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
	a.nodeInfo = nodeInfo
}

func (a *App) NodeInfo() *model.NodeInfo {
	return a.nodeInfo
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
	a.obfsProtocolService = obfsProtocolService
}

func (a *App) GetObfsProtocolService() ObfsProtocolService {
	return a.obfsProtocolService
}
