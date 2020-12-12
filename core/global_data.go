package core

import (
	"github.com/rc452860/vnet/model"
	"github.com/robfig/cron"
	"github.com/stackimpact/stackimpact-go"
)

var (
	app = NewApp()
)

func NewApp() *App {
	app := new(App)
	app.cron = cron.New()
	app.cron.Start()
	return app
}

func GetApp() *App {
	return app
}

type App struct {
	nodeInfo            *model.NodeInfo
	userInfos           []*model.UserInfo
	nodeId              int
	apiHost             string
	key                 string
	host                string
	publicIP            string
	cron                *cron.Cron
	agent               *stackimpact.Agent
	obfsProtocolService ObfsProtocolService
}

func (a *App) Init() error {
	return nil
}

func (a *App) Cron() *cron.Cron {
	return a.cron
}

func (a *App) SetCron(cron *cron.Cron) {
	a.cron = cron
}

func (a *App) UserInfos() []*model.UserInfo {
	return a.userInfos
}

func (a *App) SetUserInfos(userInfos []*model.UserInfo) {
	a.userInfos = userInfos
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

func (a *App) SetPublicIP(publicIp string) {
	a.publicIP = publicIp
}

func (a *App) GetPublicIP() string {
	return a.publicIP
}

func (a *App) SetAgent(agent *stackimpact.Agent) {
	a.agent = agent
}

func (a *App) GetAgent() *stackimpact.Agent {
	return a.agent
}

func (a *App) SetObfsProtocolService(obfsProtocolService ObfsProtocolService) {
	a.obfsProtocolService = obfsProtocolService
}

func (a *App) GetObfsProtocolService() ObfsProtocolService {
	return a.obfsProtocolService
}
