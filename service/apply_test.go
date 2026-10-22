package service

import (
	"bytes"
	"errors"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/model"
	"github.com/sirupsen/logrus"
)

// 这些用例只走不建监听器的分支（同 uid 同内容视为无需变动、缺席即摘除、端口上本来没有进程），
// 因此不需要真实端口与面板。

func TestMain(m *testing.M) {
	// delUserReturl 会读承载模式；0 = 每用户独立端口，走「端口上没有进程就当没这个人」的分支
	core.GetApp().SetNodeInfo(&model.NodeInfo{Single: 0})
	m.Run()
}

func TestReportTrafficDrainsAndRequeuesOnFailure(t *testing.T) {
	// 基数都取在起报门槛之上：这条用例测的是取批、整批重发与新批换 id，
	// 门槛拦下的字节怎么累计与强制冲刷由 traffic_port_test.go 覆盖
	s := NewShadowsocksrService()
	s.traffic[1] = &model.UserTraffic{Uid: 1, Upload: reportMin, Download: 200}
	s.traffic[2] = &model.UserTraffic{Uid: 2, Upload: reportMin}

	first := s.ReportTraffic()

	if len(first) != 2 {
		t.Fatalf("两份增量都要上报: %+v", first)
	}
	if len(s.traffic) != 0 {
		t.Fatalf("上报后待上报表应清空: %+v", s.traffic)
	}
	if first[0].ReportID == "" || first[0].ReportID != first[1].ReportID {
		t.Fatalf("同一批的所有行要共用一个非空 report_id: %+v", first)
	}

	// 发送失败：整批留在原地等重发，report_id 不变，面板据此把这批只算一次
	s.requeueTraffic(first)
	s.traffic[1] = &model.UserTraffic{Uid: 1, Upload: reportMin} // 清账之后又累计到的量

	second := s.ReportTraffic()

	if !reflect.DeepEqual(second, first) {
		t.Fatalf("重发的必须是同一批、同一个 report_id，而不是与新量合并后的结果: %+v", second)
	}

	third := s.ReportTraffic()

	if len(third) != 1 || third[0].Uid != 1 || third[0].Upload != reportMin {
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

// 在线批次与流量同一套语义：没送达就整批原样重发（report_id 不变，面板据此去重），
// 绝不并回 s.online——并回会让集合排不空、把同一批人每分钟重复上报成新的在线行
func TestReportOnlineDrainsAndRequeuesOnFailure(t *testing.T) {
	s := NewShadowsocksrService()
	// Online() 经 IdentityToUid 反查账号；测试里直接铺身份编号→uid 的索引
	s.identityIndex[1] = 1
	s.identityIndex[2] = 2
	s.Online(1, "1.2.3.4:1000")
	s.Online(2, "5.6.7.8:1000")

	first := s.ReportOnline()

	if len(first) != 2 {
		t.Fatalf("两个在线账号都要上报: %+v", first)
	}
	if len(s.online) != 0 {
		t.Fatalf("上报后待上报表应清空: %+v", s.online)
	}
	if first[0].ReportID == "" || first[0].ReportID != first[1].ReportID {
		t.Fatalf("同一批的所有行要共用一个非空 report_id: %+v", first)
	}

	s.requeueOnline(first)
	s.Online(1, "9.9.9.9:1000") // 重投期间又连上来的

	second := s.ReportOnline()

	if !reflect.DeepEqual(second, first) {
		t.Fatalf("重发的必须是同一批、同一个 report_id，而不是与新连接合并后的结果: %+v", second)
	}

	third := s.ReportOnline()

	if len(third) != 1 || third[0].Uid != 1 || third[0].IP != "9.9.9.9" {
		t.Fatalf("重投期间的新连接要留在待上报表里，不能丢: %+v", third)
	}
	if third[0].ReportID == first[0].ReportID {
		t.Fatalf("新一批必须换新 report_id，否则会被面板当成旧那批丢掉: %+v vs %+v", third, first)
	}
}

func TestApplyUserDropsDisabledAccount(t *testing.T) {
	s := NewShadowsocksrService()
	s.userTable[1] = &model.UserInfo{Uid: 1, Port: 1001, Passwd: "p", Enable: 1}

	// enable=0 的目标状态 = 摘掉账号；端口上没有进程时按「已摘掉」处理，不算失败
	if err := s.ApplyUsers(SourcePush, []*model.UserInfo{{Uid: 1, Port: 1001, Passwd: "p", Enable: 0}}); err != nil {
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
	if err := s.ApplyUsers(SourcePush, []*model.UserInfo{{Uid: 1, Port: 1001, Passwd: "p", Limit: 0, Enable: 1}}); err != nil {
		t.Fatalf("内容一致的重复下发不该报错: %s", err.Error())
	}

	if s.userTable[1] != user {
		t.Fatalf("内容一致时不该重建记录")
	}
}

func TestPlanApplyNamesTheActionForEachRow(t *testing.T) {
	for _, tc := range []struct {
		name   string
		before *model.UserInfo
		target *model.UserInfo
		want   applyAction
	}{
		{"表里没有这个 uid 是建号", nil, &model.UserInfo{Uid: 3, Port: 1003, Passwd: "r", Enable: 1}, applyAdd},
		{"内容一致什么都不动", &model.UserInfo{Uid: 1, Port: 1001, Passwd: "p", Enable: 1}, &model.UserInfo{Uid: 1, Port: 1001, Passwd: "p", Enable: 1}, applyNone},
		{"端口变了是换号", &model.UserInfo{Uid: 2, Port: 1002, Passwd: "q", Enable: 1}, &model.UserInfo{Uid: 2, Port: 1004, Passwd: "q", Enable: 1}, applyEdit},
		{"限速变了也是换号", &model.UserInfo{Uid: 2, Port: 1002, Passwd: "q", Limit: 0, Enable: 1}, &model.UserInfo{Uid: 2, Port: 1002, Passwd: "q", Limit: 1048576, Enable: 1}, applyEdit},
		{"enable=0 且表里有行是摘号", &model.UserInfo{Uid: 1, Port: 1001, Passwd: "p", Enable: 1}, &model.UserInfo{Uid: 1, Port: 1001, Passwd: "p", Enable: 0}, applyRemove},
		{"enable=0 但表里没行不算变更", nil, &model.UserInfo{Uid: 9, Port: 1009, Passwd: "z", Enable: 0}, applyNone},
	} {
		if got := planApply(tc.before, tc.target); got != tc.want {
			t.Fatalf("%s: action = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// 删除是「落目标状态」而不是「执行一次动词」：同一 uid 重投必须成功
func TestDelUserIsIdempotent(t *testing.T) {
	s := NewShadowsocksrService()
	s.userTable[1] = &model.UserInfo{Uid: 1, Port: 1001, Passwd: "p", Enable: 1}

	if err := s.DelUser(1); err != nil {
		t.Fatalf("首次删除失败: %s", err.Error())
	}
	if err := s.DelUser(1); err != nil {
		t.Fatalf("重复删除不该失败: %s", err.Error())
	}
	if len(s.userTable) != 0 {
		t.Fatalf("删除后用户表仍有残留: %+v", s.userTable)
	}
}

// 批量删除里混入已不存在的 uid 不能回滚整批：否则丢失响应后的重投永远成功不了
func TestDelUsersSkipsAbsentUID(t *testing.T) {
	s := NewShadowsocksrService()
	s.userTable[1] = &model.UserInfo{Uid: 1, Port: 1001, Passwd: "p", Enable: 1}

	if err := s.DelUsers([]int{1, 2}); err != nil {
		t.Fatalf("含缺席 uid 的批量删除不该失败: %s", err.Error())
	}
	if len(s.userTable) != 0 {
		t.Fatalf("批量删除后用户表仍有残留: %+v", s.userTable)
	}
}

// 周期同步取数期间有推送落地时，旧快照必须整份丢弃：否则新账号会被删掉、新密码会被覆盖回去
func TestStaleUserSnapshotIsDiscarded(t *testing.T) {
	s := NewShadowsocksrService()
	s.userTable[1] = &model.UserInfo{Uid: 1, Port: 1001, Passwd: "p", Enable: 1}
	gen := s.UsersGeneration()

	if err := s.ApplyUsersFromPush([]*model.UserInfo{{Uid: 2, Port: 1002, Passwd: "q", Enable: 0}}); err != nil {
		t.Fatalf("推送落地失败: %s", err.Error())
	}
	if err := s.SyncUsersIfUnchanged([]*model.UserInfo{}, gen); !errors.Is(err, ErrStaleUserSnapshot) {
		t.Fatalf("取数期间的推送没有让快照作废: %v", err)
	}
	if s.userTable[1] == nil {
		t.Fatal("旧快照仍然把本地用户删掉了")
	}

	// 当前代次的快照照常应用：缺席的 uid 被摘掉
	if err := s.SyncUsersIfUnchanged([]*model.UserInfo{}, s.UsersGeneration()); err != nil {
		t.Fatalf("当前代次快照应用失败: %s", err.Error())
	}
	if len(s.userTable) != 0 {
		t.Fatalf("当前快照没有收敛本地用户表: %+v", s.userTable)
	}
}

// Start 失败时不能把没有 listener、也没有用户行的 proxy 留在端口索引里，
// 否则后续每次重试都撞「端口已占用」，直到整节点重载
func TestAddUserBindFailureDoesNotLeakPortEntry(t *testing.T) {
	prevHost := core.GetApp().Host()
	core.GetApp().SetHost("127.0.0.1")
	t.Cleanup(func() { core.GetApp().SetHost(prevHost) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	s := NewShadowsocksrService()
	err = s.ApplyUsers(SourcePush, []*model.UserInfo{{Uid: 1, Port: port, Passwd: "p", Enable: 1}})
	if err == nil {
		t.Fatal("端口已被占用时 addUser 竟然成功了")
	}
	if got := s.lookupProxy(port); got != nil {
		t.Fatalf("Start 失败后端口索引里留下了残条目: %+v", got)
	}
	if len(s.userTable) != 0 {
		t.Fatalf("Start 失败后用户表里留下了残行: %+v", s.userTable)
	}
}

// 退出路径可能被重复调用（信号处理与测试清理）：不能因为没启动过就 nil 解引用
func TestShutdownWithoutStartIsIdempotent(t *testing.T) {
	s := NewShadowsocksrService()
	s.Shutdown()
	s.Shutdown()
}

// 日志要跟着实际动作走：全量下发里绝大多数账号是没变的，逐行记就成了「什么任务在刷 apply」查不清。
// 这里只走不建监听器的分支（摘表里的行与不动），所以端口不用真的监听。
func TestApplyUsersLogsOnlyChangedRows(t *testing.T) {
	var buf bytes.Buffer
	out, level := logrus.StandardLogger().Out, logrus.GetLevel()
	logrus.SetOutput(&buf)
	logrus.SetLevel(logrus.InfoLevel)
	t.Cleanup(func() {
		logrus.SetOutput(out)
		logrus.SetLevel(level)
	})

	s := NewShadowsocksrService()
	s.userTable[1] = &model.UserInfo{Uid: 1, Port: 1001, Passwd: "p", Enable: 1}
	s.userTable[2] = &model.UserInfo{Uid: 2, Port: 1002, Passwd: "q", Enable: 1}

	applyLines := func() []string {
		var hits []string
		for _, line := range strings.Split(buf.String(), "\n") {
			if strings.Contains(line, "apply user ") {
				hits = append(hits, line)
			}
		}
		return hits
	}

	// 三个账号：1 没变、2 是 enable=0 要摘掉、3 本来就不在表里
	if err := s.ApplyUsers(SourcePoll, []*model.UserInfo{
		{Uid: 1, Port: 1001, Passwd: "p", Enable: 1},
		{Uid: 2, Port: 1002, Passwd: "q", Enable: 0},
		{Uid: 3, Port: 1003, Passwd: "r", Enable: 0},
	}); err != nil {
		t.Fatalf("下发失败: %s", err.Error())
	}

	lines := applyLines()
	if len(lines) != 1 {
		t.Fatalf("只有真的动了表的那一行该有日志: %q", buf.String())
	}
	for _, want := range []string{"apply user remove", "uid: 2", "source: poll"} {
		if !strings.Contains(lines[0], want) {
			t.Fatalf("日志行 %q 缺 %q", lines[0], want)
		}
	}
	if strings.Contains(buf.String(), "apply users no change") {
		t.Fatalf("这批动了账号，不该出现「没变动」的标记: %q", buf.String())
	}

	buf.Reset()

	// 同一批原样重投：不逐行记，但要留一行「这批没动到任何人」，否则日志里看不出这一轮发生过什么
	if err := s.ApplyUsers(SourcePoll, []*model.UserInfo{
		{Uid: 1, Port: 1001, Passwd: "p", Enable: 1},
	}); err != nil {
		t.Fatalf("重投失败: %s", err.Error())
	}
	if got := applyLines(); len(got) != 0 {
		t.Fatalf("内容一致的批次不该逐行产生日志: %q", buf.String())
	}
	marker := ""
	for _, line := range strings.Split(buf.String(), "\n") {
		if strings.Contains(line, "apply users no change") {
			marker = line
		}
	}
	for _, want := range []string{"source: poll", "total: 1"} {
		if !strings.Contains(marker, want) {
			t.Fatalf("空转批次留下的标记缺 %q: %q", want, buf.String())
		}
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
