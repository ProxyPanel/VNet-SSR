package main

import (
	"github.com/ProxyPanel/VNet-SSR/api/client"
	"github.com/ProxyPanel/VNet-SSR/api/server"
	"github.com/ProxyPanel/VNet-SSR/cmd/shadowsocksr-server/command"
	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/common/obfs"
	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/service"
	"github.com/ProxyPanel/VNet-SSR/utils/addrx"
	"github.com/ProxyPanel/VNet-SSR/utils/osx"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func main() {
	logrus.SetLevel(logrus.InfoLevel)
	command.Execute(func() {
		if err := core.GetApp().Init(); err != nil {
			panic(err)
		}
		core.GetApp().SetApiHost(viper.GetString(command.API_HOST))
		core.GetApp().SetNodeId(viper.GetInt(command.NODE_ID))
		core.GetApp().SetKey(viper.GetString(command.KEY))
		core.GetApp().SetHost(viper.GetString(command.HOST))
		if err := client.InitHost(); err != nil {
			panic(err)
		}

		nodeInfo, err := client.GetNodeInfo()
		if err != nil {
			logrus.Fatal(err)
		}
		core.GetApp().SetNodeInfo(nodeInfo)
		// 空 secret 的节点等于把 push 端口开放给任何能连上它的人（可改用户表、重载配置）；
		// 单端口配上不携带账号身份的协议则无法归属任何流量。都不带着这种配置继续跑
		if err := server.ValidateNodeInfo(nodeInfo); err != nil {
			logrus.Fatal(err)
		}
		logrus.WithFields(logrus.Fields{
			"id":          nodeInfo.ID,
			"port":        nodeInfo.Port,
			"method":      nodeInfo.Method,
			"protocol":    nodeInfo.Protocol,
			"obfs":        nodeInfo.Obfs,
			"pushPort":    nodeInfo.PushPort,
			"single":      nodeInfo.Single,
			"isUdp":       nodeInfo.IsUDP,
			"clientLimit": nodeInfo.ClientLimit,
			"speedLimit":  nodeInfo.SpeedLimit,
		}).Info("get node info success")

		core.GetApp().SetObfsProtocolService(obfs.NewObfsAuthChainData(nodeInfo.Protocol))
		if nodeInfo.ClientLimit != 0 {
			log.Info("set client limit with %v", nodeInfo.ClientLimit)
			core.GetApp().GetObfsProtocolService().SetMaxClient(nodeInfo.ClientLimit)
		} else {
			log.Info("ignore client limit, because client_limit is zero, use default limit is 64")
		}

		if err := service.Start(); err != nil {
			panic(err)
		}

		if err := server.StartServer(nodeInfo.PushPort, nodeInfo.Secret); err != nil {
			logrus.Fatal(err)
		}
		go probeEgress()
		sig := osx.WaitSignal()
		logrus.Infof("received signal %v, shutting down", sig)
		_ = server.StopServer()
		service.GetSSRManager().Shutdown()
	})
}

// probeEgress 只打一行观测日志：这个值没有任何消费方，所以绝不能挡在启动路径上——
// 放在解析配置之前做同步 GET 并在失败时 panic，外部站点不可达就会被 systemd 拖进无限重启循环
func probeEgress() {
	for _, probe := range []struct{ family, url string }{
		{"ipv4", "https://api-ipv4.ip.sb/ip"},
		{"ipv6", "https://api-ipv6.ip.sb/ip"},
	} {
		ip, err := addrx.GetPublicIp(probe.url)
		if err != nil {
			logrus.Warnf("探测对外地址(%s)失败: %s", probe.family, err.Error())
			continue
		}

		logrus.Infof("探测到对外地址(%s): %s", probe.family, ip)
	}
}
