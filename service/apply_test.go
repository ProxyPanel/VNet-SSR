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
	if first[0].ReportID == "" || first[0].ReportID != first[1].ReportID {
		t.Fatalf("同一批的所有行要共用一个非空 report_id: %+v", first)
	}

	// 发送失败：整批留在原地等重发，report_id 不变，面板据此把这批只算一次
	s.requeueTraffic(first)
	s.traffic[1] = &model.UserTraffic{Uid: 1, Upload: 50} // 清账之后又累计到的量

	second := s.ReportTraffic()

	if !reflect.DeepEqual(second, first) {
		t.Fatalf("重发的必须是同一批、同一个 report_id，而不是与新量合并后的结果: %+v", second)
	}

	third := s.ReportTraffic()

	if len(third) != 1 || third[0].Uid != 1 || third[0].Upload != 50 {
		t.Fatalf("重发期间累计的字节要留在待上报表里，不能丢: %+v", third)
	}
	if third[0].ReportID == first[0].ReportID {
		t.Fatalf("新一批必须换新 report_id，否则会被面板当成旧那批丢掉: %+v vs %+v", third, first)
	}
}

func TestReportTrafficSkipsUnattributableBytes(t *testing.T) {
	s := NewShadowsocksrService()
	// uid 0 来自端口查不到账号的连接，面板不会收，留着只会越积越大
	s.traffic[0] = &model.UserTraffic{Uid: 0, Upload: 9999}

	if got := s.ReportTraffic(); len(got) != 0 {
		t.Fatalf("uid 0 不该进上报批次: %+v", got)
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

// TestUserTableReadersConcurrentWithSync 钉住这一点：读侧（GET /api/user/list、Close 时的 GetUids）
// 与后台 SyncUsers 的写并发时，遍历必须在锁内。
// 不加锁时这里不是 data race 而是 runtime 的 "concurrent map read and map write" 致命错误，
// recover 拦不住，整个进程会没——所以这条测试挂了就是节点会挂。
func TestUserTableReadersConcurrentWithSync(t *testing.T) {
	const total = 200

	s := NewShadowsocksrService()
	all := make([]*model.UserInfo, 0, total)
	for i := 0; i < total; i++ {
		user := &model.UserInfo{Uid: i + 1, Port: 1000 + i, Passwd: "p", Enable: 1}
		s.userTable[user.Uid] = user
		all = append(all, user)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		// 写侧：每轮少一个账号，逐行从表里删掉（端口上没有监听器，走的是纯清表分支）
		for i := total; i >= 0; i-- {
			if err := s.SyncUsers(all[:i]); err != nil {
				t.Errorf("sync failed: %s", err.Error())
				return
			}
		}
	}()

	for {
		select {
		case <-done:
			if got := len(s.GetUserList()); got != 0 {
				t.Fatalf("全部账号都该被摘掉: %v", got)
			}
			return
		default:
			_ = s.GetUserList()
			_ = s.GetUids()
		}
	}
}
