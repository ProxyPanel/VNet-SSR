package client

import (
	"fmt"
	"testing"

	"github.com/rc452860/vnet/model"
	"github.com/sirupsen/logrus"
)

func ExampleGetNodeInfo() {
	HOST = "http://localhost"
	logrus.SetLevel(logrus.DebugLevel)
	result, _ := GetNodeInfo(2, "txsnvhghmrmg4pjm")
	fmt.Printf("value: %+v \n", result)
	//Output:
}

func ExampleGetUserList() {
	HOST = "http://dash.kitami.ml"
	logrus.SetLevel(logrus.DebugLevel)
	result, _ := GetUserList(1, "vrrwwnprz6cmytzp")
	fmt.Printf("value: %+v\n", result)
	//Output:
}

func ExamplePostAllUserTraffic() {
	HOST = "http://localhost"
	logrus.SetLevel(logrus.DebugLevel)
	PostAllUserTraffic([]*model.UserTraffic{
		{
			1, 200, 200, 0, 0,
		},
	}, 1, "txsnvhghmrmg4pjm")
	//Output:
}

func ExamplePostNodeOnline() {
	HOST = "http://localhost"
	logrus.SetLevel(logrus.DebugLevel)
	PostNodeOnline([]*model.NodeOnline{
		{
			1,
			"192.168.1.1",
		},
	}, 1, "txsnvhghmrmg4pjm")
	//Output:
}

func ExamplePostNodeStatus() {
	HOST = "http://localhost"
	logrus.SetLevel(logrus.DebugLevel)
	PostNodeStatus(model.NodeStatus{
		CPU:    "10%",
		MEM:    "10%",
		DISK:   "10",
		NET:    "up: 50kb,down: 50kb",
		UPTIME: 2000,
	}, 1, "txsnvhghmrmg4pjm")

	//Output:
}

func ExampleHasCertifacation() {
	fmt.Println(HasCertification("https://ignet.app"))
	fmt.Println(HasCertification("https://ignet.app"))
	//Output:
}

func TestGetNodeRule(t *testing.T) {
	HOST = "http://ss.local3.com"
	model, err := GetNodeRule(1, "6pqhmuyd4yxeazs5")
	if err != nil {
		t.Fatal(fmt.Sprintf("%+v", err))
		return
	}
	fmt.Printf("%+v\n", model)
}
