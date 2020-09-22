package main

import (
	server2 "github.com/rc452860/vnet/proxy/server"
	"github.com/rc452860/vnet/service"
	"github.com/rc452860/vnet/utils/osx"
	"github.com/sirupsen/logrus"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	//go func() {
	//	log.Println(http.ListenAndServe("0.0.0.0:445", nil))
	//}()
	Test2()
}

func Test2() {
	logrus.SetLevel(logrus.InfoLevel)
	TestShadowsocksr()
	// Wait for interrupt signal to gracefully shutdown the server with
	// a timeout of 5 seconds.
	quit := make(chan os.Signal)
	// kill (no param) default send syscall.SIGTERM
	// kill -2 is syscall.SIGINT
	// kill -9 is syscall.SIGKILL but can't be catch, so don't need add it
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
}

func TestShadowsocksr() {
	//service.GetRuleService().Load(&model.Rule{
	//	Model: service.RULE_MODE_REJECT,
	//	Rules: []model.RuleItem{
	//		{
	//			Id:      1,
	//			Type:    service.RULE_TYPE_REG,
	//			Pattern: "(.*\\.||)(dafahao|minghui|dongtaiwang|epochtimes|ntdtv|falundafa|wujieliulan|zhengjian)\\.(org|com|net)",
	//		},
	//	},
	//})
	//service.GetLimitInstance().Set(3718, 1024*400)

	//logrus.SetLevel(logrus.DebugLevel)
	server := server2.ShadowsocksRProxy{
		Port:             12500,
		Host:             "0.0.0.0",
		Method:           "aes-128-gcm",
		Password:         "killer",
		Protocol:         "origin",
		Obfs:             "plain",
		ObfsParam:        "",
		Single:           0,
		ShadowsocksRArgs: &server2.ShadowsocksRArgs{},
		HostFirewall:     service.GetRuleService(),
		ILimiter:         service.GetLimitInstance(),
	}
	//server.AddUser(1200, "killer")
	if err := server.Start();err != nil{
		panic(err)
		return
	}
	//// Wait for interrupt signal to gracefully shutdown the server with
	//// a timeout of 5 seconds.
	//quit := make(chan os.Signal)
	//// kill (no param) default send syscall.SIGTERM
	//// kill -2 is syscall.SIGINT
	//// kill -9 is syscall.SIGKILL but can't be catch, so don't need add it
	//signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL)
	//<-quit
	osx.WaitSignal()
}
