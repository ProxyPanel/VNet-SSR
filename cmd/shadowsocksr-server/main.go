package main

import (
	"fmt"
	"github.com/rc452860/vnet/api/client"
	"github.com/rc452860/vnet/api/server"
	"github.com/rc452860/vnet/cmd/shadowsocksr-server/command"
	"github.com/rc452860/vnet/common/log"
	"github.com/rc452860/vnet/common/obfs"
	"github.com/rc452860/vnet/core"
	"github.com/rc452860/vnet/service"
	"github.com/rc452860/vnet/utils/addrx"
	"github.com/rc452860/vnet/utils/osx"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func main() {
	logrus.SetLevel(logrus.InfoLevel)
	ip, err := addrx.GetPublicIp()
	if err != nil {
		panic(err)
	}
	command.Execute(func() {
		if err := core.GetApp().Init(); err != nil {
			panic(err)
		}
		core.GetApp().SetApiHost(viper.GetString(command.API_HOST))
		core.GetApp().SetNodeId(viper.GetInt(command.NODE_ID))
		core.GetApp().SetKey(viper.GetString(command.KEY))
		core.GetApp().SetHost(viper.GetString(command.HOST))
		core.GetApp().SetPublicIP(ip)
		if core.GetApp().GetPublicIP() == "" {
			panic("get public ip error,please try align")
		}
		log.Info("get public ip %s", core.GetApp().GetPublicIP())

		client.SetHost(core.GetApp().ApiHost())

		nodeInfo, err := client.GetNodeInfo(core.GetApp().NodeId(), viper.GetString(command.KEY))
		if err != nil {
			logrus.Fatal(err)
		}
		core.GetApp().SetNodeInfo(nodeInfo)
		logrus.WithFields(logrus.Fields{
			"nodeInfo": fmt.Sprintf("%+v", nodeInfo),
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
			return
		}

		server.StartServer(nodeInfo.PushPort, nodeInfo.Secret)
		osx.WaitSignal()
	})
}
