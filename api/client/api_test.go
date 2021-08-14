package client

import (
	"fmt"
	"testing"

	"github.com/ProxyPanel/VNet-SSR/model"
	"github.com/sirupsen/logrus"
)

func ExampleGetNodeInfo() {
	Host = "http://localhost"
	logrus.SetLevel(logrus.DebugLevel)
	result, _ := GetNodeInfo()
	fmt.Printf("value: %+v \n", result)
	//Output:
}

func ExampleGetUserList() {
	Host = "http://dash.kitami.ml"
	logrus.SetLevel(logrus.DebugLevel)
	result, _ := GetUserList()
	fmt.Printf("value: %+v\n", result)
	//Output:
}

func ExamplePostAllUserTraffic() {
	Host = "http://localhost"
	logrus.SetLevel(logrus.DebugLevel)
	PostAllUserTraffic([]*model.UserTraffic{
		{
			1, 200, 200, 0, 0,
		},
	})
	//Output:
}

func ExamplePostNodeOnline() {
	Host = "http://localhost"
	logrus.SetLevel(logrus.DebugLevel)
	PostNodeOnline([]*model.NodeOnline{
		{
			1,
			"192.168.1.1",
		},
	})
	//Output:
}

func ExamplePostNodeStatus() {
	Host = "http://localhost"
	logrus.SetLevel(logrus.DebugLevel)
	PostNodeStatus(model.NodeStatus{
		CPU:    "10%",
		MEM:    "10%",
		DISK:   "10",
		NET:    "up: 50kb,down: 50kb",
		UPTIME: 2000,
	})

	//Output:
}

func TestGetNodeRule(t *testing.T) {
	Host = "http://ss.local3.com"
	model, err := GetNodeRule()
	if err != nil {
		t.Fatal(fmt.Sprintf("%+v", err))
		return
	}
	fmt.Printf("%+v\n", model)
}
