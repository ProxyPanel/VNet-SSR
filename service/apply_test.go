package service

import (
	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/model"
	"reflect"
	"testing"
)

// 这些用例只走不建监听器的分支（同 uid 同内容视为无需变动、缺席即摘除、端口上本来没有进程），
// 因此不需要真实端口与面板。

func TestMain(m *testing.M) {
	// delUserReturl 会读承载模式；0 = 每用户独立端口，走「端口上没有进程就当没这个人」的分支
	core.GetApp().SetNodeInfo(&model.NodeInfo{Single: 0})
	m.Run()
}

func TestReportTrafficDrainsAndRequeuesOnFailure(t *testing.T) {
	s := NewShadowsocksrService()
	s.traffic[1] = &model.UserTraffic{Uid: 1, Upload: 100, Download: 200}
	s.traffic[2] = &model.UserTraffic{Uid: 2, Upload: 1, Download: 1}

	first := s.ReportTraffic()

	if len(first) != 2 {
		t.Fatalf("两份增量都要上报（小流量不再被门槛吃掉）: %+v", first)
	}
	if len(s.traffic) != 0 {
		t.Fatalf("上报后待上报表应清空: %+v", s.traffic)
	}

	// 发送失败：并回待上报表，同一批字节不能只存在于这一份快照里
	s.requeueTraffic(first)
	s.traffic[1].Upload += 50 // 清账之后又累计到的量必须保留

	second := s.ReportTraffic()

	if len(second) != 2 {
		t.Fatalf("并回后两条记录都要还在: %+v", second)
	}

	var uid1 *model.UserTraffic

	for _, item := range second {
		if item.Uid == 1 {
			uid1 = item
		}
	}

	if uid1 == nil || uid1.Upload != 150 || uid1.Download != 200 {
		t.Fatalf("并回的是这一轮没送达的增量，之后累计的量要留在同一行上: %+v", uid1)
	}
}

func TestRequeueTrafficSkipsUnattributableBytes(t *testing.T) {
	s := NewShadowsocksrService()
	// uid 0 来自端口查不到账号的连接，面板不会收，留着只会越积越大
	s.requeueTraffic([]*model.UserTraffic{{Uid: 0, Upload: 9999}})

	if len(s.traffic) != 0 {
		t.Fatalf("uid 0 不该被并回: %+v", s.traffic)
	}
}

func TestApplyUserDropsDisabledAccount(t *testing.T) {
	s := NewShadowsocksrService()
	s.userTable[1] = &model.UserInfo{Uid: 1, Port: 1001, Passwd: "p", Enable: 1}

	// enable=0 的目标状态 = 摘掉账号；端口上没有进程时按「已摘掉」处理，不算失败
	if err := s.ApplyUsers([]*model.UserInfo{{Uid: 1, Port: 1001, Passwd: "p", Enable: 0}}); err != nil {
		t.Fatalf("禁用账号的下发不该报错: %s", err.Error())
	}

	if _, exist := s.userTable[1]; exist {
		t.Fatalf("enable=0 的用户要离开用户表")
	}
}

func TestApplyUserIsIdempotent(t *testing.T) {
	s := NewShadowsocksrService()
	user := &model.UserInfo{Uid: 1, Port: 1001, Passwd: "p", Limit: 0, Enable: 1}
	s.userTable[1] = user

	// 已存在且内容一致：不再建监听器，重投同一批不会多出什么
	if err := s.ApplyUsers([]*model.UserInfo{{Uid: 1, Port: 1001, Passwd: "p", Limit: 0, Enable: 1}}); err != nil {
		t.Fatalf("内容一致的重复下发不该报错: %s", err.Error())
	}

	if s.userTable[1] != user {
		t.Fatalf("内容一致时不该重建记录")
	}
}

func TestSyncUsersRemovesAccountsAbsentFromPanel(t *testing.T) {
	s := NewShadowsocksrService()
	keep := &model.UserInfo{Uid: 1, Port: 1001, Passwd: "p", Enable: 1}
	stale := &model.UserInfo{Uid: 2, Port: 1002, Passwd: "q", Enable: 1}
	s.userTable[1] = keep
	s.userTable[2] = stale

	if err := s.SyncUsers([]*model.UserInfo{{Uid: 1, Port: 1001, Passwd: "p", Enable: 1}}); err != nil {
		t.Fatalf("同步失败: %s", err.Error())
	}

	uids := make([]int, 0, len(s.userTable))

	for uid := range s.userTable {
		uids = append(uids, uid)
	}

	if !reflect.DeepEqual(uids, []int{1}) {
		t.Fatalf("面板集合里没有的 uid 要被摘掉: %+v", uids)
	}
}
