package client

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/model"
)

type recorded struct {
	method string
	path   string
	key    string
	ts     string
	etag   string
	body   string
}

// newPanel 起一个假面板，把每个请求记进 got；resp 决定响应（可按第几次调用分支）。
func newPanel(t *testing.T, got *[]recorded, resp func(r recorded) (status int, header http.Header, body string)) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec := recorded{
			method: r.Method,
			path:   r.URL.Path,
			key:    r.Header.Get("key"),
			ts:     r.Header.Get("timestamp"),
			etag:   r.Header.Get("If-None-Match"),
			body:   string(body),
		}
		*got = append(*got, rec)

		status, header, payload := resp(rec)
		for name, values := range header {
			for _, v := range values {
				w.Header().Add(name, v)
			}
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(payload))
	}))
	t.Cleanup(server.Close)
	return server
}

// usePanel 把包级 Host 与 core 里的节点身份指向假面板，测完还原。
func usePanel(t *testing.T, server *httptest.Server) {
	t.Helper()
	prevHost, prevID, prevKey, prevPublic := core.GetApp().ApiHost(), core.GetApp().NodeId(), core.GetApp().Key(), Host
	t.Cleanup(func() {
		core.GetApp().SetApiHost(prevHost)
		core.GetApp().SetNodeId(prevID)
		core.GetApp().SetKey(prevKey)
		Host = prevPublic
		userListEtag.Store("")
	})

	core.GetApp().SetApiHost(server.URL)
	core.GetApp().SetNodeId(7)
	core.GetApp().SetKey("node-secret")
	if err := InitHost(); err != nil {
		t.Fatalf("InitHost 失败: %s", err.Error())
	}
}

func okJSON(body string) (int, http.Header, string) {
	return http.StatusOK, http.Header{}, body
}

func TestInitHostBuildsPanelBase(t *testing.T) {
	defer func(previous string) { Host = previous }(Host)

	core.GetApp().SetApiHost("")
	if err := InitHost(); err == nil {
		t.Fatal("api_host 为空时应该拒绝拼基址，否则会带着 host-less URL 启动")
	}

	core.GetApp().SetApiHost("panel.example.com")
	if err := InitHost(); err == nil {
		t.Fatal("api_host 缺 scheme 时应该报错")
	}

	core.GetApp().SetApiHost("https://panel.example.com/")
	if err := InitHost(); err != nil {
		t.Fatalf("合法的 api_host 不该报错: %s", err.Error())
	}
	if Host != "https://panel.example.com/api/ssr/v1" {
		t.Fatalf("Host = %q, want https://panel.example.com/api/ssr/v1（尾部斜杠要裁掉）", Host)
	}
}

func TestGetNodeInfoSendsAuthHeadersAndParsesPayload(t *testing.T) {
	var got []recorded
	payload := `{"status":"success","data":{"id":7,"port":"8388","passwd":"killer","method":"aes-256-cfb",` +
		`"protocol":"auth_chain_a","obfs":"tls1.2_ticket_auth","push_port":30108,"secret":"push-secret",` +
		`"single":1,"is_udp":1,"client_limit":32,"speed_limit":1048576}}`
	server := newPanel(t, &got, func(recorded) (int, http.Header, string) { return okJSON(payload) })
	usePanel(t, server)

	info, err := GetNodeInfo()
	if err != nil {
		t.Fatalf("GetNodeInfo 失败: %s", err.Error())
	}
	if info.Port != "8388" || info.PushPort != 30108 || info.Secret != "push-secret" || info.SpeedLimit != 1048576 {
		t.Fatalf("节点配置解析不符: %+v", info)
	}

	if len(got) == 0 {
		t.Fatal("假面板没收到请求")
	}
	req := got[0]
	if req.path != "/api/ssr/v1/node/7" {
		t.Fatalf("路径 = %q, want /api/ssr/v1/node/7", req.path)
	}
	if req.key != "node-secret" {
		t.Fatalf("key 头 = %q, want node-secret（面板按它认节点）", req.key)
	}
	// 面板要求两侧时差 <300 秒，timestamp 必须是 unix 秒而不是毫秒
	seconds, err := strconv.ParseInt(req.ts, 10, 64)
	if err != nil {
		t.Fatalf("timestamp 头不是整数: %q", req.ts)
	}
	if diff := time.Now().Unix() - seconds; diff < -5 || diff > 5 {
		t.Fatalf("timestamp 偏离当前时间 %d 秒，面板会当成时钟不同步拒掉", diff)
	}
}

func TestParseNodeInfoSurfacesPanelMessage(t *testing.T) {
	if _, err := parseNodeInfo(`{"status":"fail","message":"节点不存在"}`); err == nil || err.Error() != "节点不存在" {
		t.Fatalf("面板回 fail 时要把 message 交给调用方，得到 %v", err)
	}

	if _, err := parseNodeInfo(`{"status":"success"}`); err == nil {
		t.Fatal("缺 data 的响应必须报错：否则节点会拿一份空配置去起监听")
	}
}

func TestGetWithEtagTreats304AsUnchanged(t *testing.T) {
	var got []recorded
	handler := func(r recorded) (int, http.Header, string) {
		if r.etag == "etag-1" {
			return http.StatusNotModified, http.Header{}, ""
		}
		return http.StatusOK, http.Header{"Etag": []string{"etag-1"}}, `{"status":"success","data":[]}`
	}
	server := newPanel(t, &got, handler)
	usePanel(t, server)

	body, changed, etag, err := getWithEtag(userListURL(), "")
	if err != nil || !changed || etag != "etag-1" {
		t.Fatalf("首拉 = (%q, %v, %q, %v), want 有内容且带 etag", body, changed, etag, err)
	}

	// 304 不是失败：按错误处理会让节点每轮都把用户表当成拉不到
	_, changed, _, err = getWithEtag(userListURL(), "etag-1")
	if err != nil {
		t.Fatalf("304 不该回错误: %s", err.Error())
	}
	if changed {
		t.Fatal("304 应判为内容未变")
	}

	failing := newPanel(t, &got, func(recorded) (int, http.Header, string) {
		return http.StatusInternalServerError, http.Header{}, `{"status":"fail","message":"boom"}`
	})
	usePanel(t, failing)
	if _, _, _, err = getWithEtag(userListURL(), ""); err == nil {
		t.Fatal("非 200 必须回错误，否则空响应会被当成用户表")
	}
}

func TestUserListPullStoresEtagAndSyncReusesIt(t *testing.T) {
	var got []recorded
	current := `[{"uid":1,"port":8388,"passwd":"killer","speed_limit":1048576,"enable":1}]`
	// 面板的 ETag 由内容哈希得来：内容变了号就变，客户端带的号只在内容没变时命中 304
	handler := func(r recorded) (int, http.Header, string) {
		etag := "etag-" + strconv.Itoa(len(current))
		if r.etag == etag {
			return http.StatusNotModified, http.Header{}, ""
		}
		return http.StatusOK, http.Header{"Etag": []string{etag}}, `{"status":"success","data":` + current + `}`
	}
	server := newPanel(t, &got, handler)
	usePanel(t, server)

	users, err := GetUserList()
	if err != nil || len(users) != 1 || users[0].Uid != 1 {
		t.Fatalf("全量拉取 = %+v, %v", users, err)
	}
	first := loadUserListEtag()
	if first == "" {
		t.Fatal("拉到的 etag 没存下来，后续同步每次都白拉全量")
	}

	// 内容未变：unchanged 为 true，调用方要保留现有服务
	synced, unchanged, err := SyncUserList()
	if err != nil || !unchanged || synced != nil {
		t.Fatalf("增量同步 = (%+v, unchanged=%v, err=%v), want unchanged 且不带用户", synced, unchanged, err)
	}
	if loadUserListEtag() != first {
		t.Fatalf("304 之后 etag 被冲掉了: %q, want %q", loadUserListEtag(), first)
	}

	// 内容变了要换新用户表并记下新 etag
	current = `[{"uid":2,"port":8389,"passwd":"other","speed_limit":0,"enable":1}]`
	synced, unchanged, err = SyncUserList()
	if err != nil || unchanged || len(synced) != 1 || synced[0].Uid != 2 {
		t.Fatalf("变更后同步 = (%+v, unchanged=%v, err=%v)", synced, unchanged, err)
	}
	if loadUserListEtag() == first {
		t.Fatal("内容已变更却没记下新 etag，下一轮会被当成未变而漏掉用户")
	}
}

// 用户表被 GET 之外的路径改过之后，手里那份哈希不再描述它：带着旧哈希轮询，面板按旧基线回 304，
// 推送丢的那一次就永远没有收敛机会。作废之后下一轮必须重新取基线
func TestMarkUserListStaleForcesNextFullFetch(t *testing.T) {
	var got []recorded
	current := `[{"uid":1,"port":8388,"passwd":"killer","speed_limit":0,"enable":1}]`
	handler := func(r recorded) (int, http.Header, string) {
		etag := "etag-" + strconv.Itoa(len(current))
		if r.etag == etag {
			return http.StatusNotModified, http.Header{}, ""
		}
		return http.StatusOK, http.Header{"Etag": []string{etag}}, `{"status":"success","data":` + current + `}`
	}
	server := newPanel(t, &got, handler)
	usePanel(t, server)

	if _, err := GetUserList(); err != nil {
		t.Fatalf("全量拉取失败: %s", err.Error())
	}
	baseline := loadUserListEtag()
	if baseline == "" {
		t.Fatal("首拉没记下基线")
	}
	// 内容原样未变时带着基线轮询，命中的是 304
	if _, unchanged, err := SyncUserList(); err != nil || !unchanged {
		t.Fatalf("内容未变应命中 304: unchanged=%v err=%v", unchanged, err)
	}

	MarkUserListStale()
	if loadUserListEtag() != "" {
		t.Fatalf("作废后仍留着基线: %q", loadUserListEtag())
	}

	before := len(got)
	synced, unchanged, err := SyncUserList()
	if err != nil || unchanged || len(synced) != 1 {
		t.Fatalf("作废基线后这一轮要重新取到全量: unchanged=%v err=%v", unchanged, err)
	}
	if got[before].etag != "" {
		t.Fatalf("作废后仍带旧基线去轮询: %q", got[before].etag)
	}
	if loadUserListEtag() == "" {
		t.Fatal("重新取到的全量要记下新基线，否则下一轮还是全量")
	}
}

// 「取不到集合」与「集合为空」是两件事：[] 是面板上确实没人，报错才是拿不到
func TestParseUserListSeparatesEmptyFromMissing(t *testing.T) {
	users, err := parseUserList(`{"status":"success","data":[]}`)
	if err != nil {
		t.Fatalf("空列表不该报错: %s", err.Error())
	}
	if len(users) != 0 {
		t.Fatalf("空列表解出 %d 条", len(users))
	}

	if _, err := parseUserList(`{"status":"fail","message":"未授权"}`); err == nil {
		t.Fatal("鉴权失败必须报错，否则整节点用户会被当成缺漏重推")
	}
}

func TestPostTrafficBatchKeepsReportIDAndPath(t *testing.T) {
	var got []recorded
	server := newPanel(t, &got, func(recorded) (int, http.Header, string) {
		return okJSON(`{"status":"success","message":"ok"}`)
	})
	usePanel(t, server)

	batch := []*model.UserTraffic{
		{Uid: 1, Upload: 100, Download: 200, ReportID: "batch-1"},
		{Uid: 2, Upload: 1, Download: 2, ReportID: "batch-1"},
	}
	if err := PostAllUserTraffic(batch); err != nil {
		t.Fatalf("上报失败: %s", err.Error())
	}

	req := got[0]
	if req.path != "/api/ssr/v1/userTraffic/7" {
		t.Fatalf("路径 = %q, want /api/ssr/v1/userTraffic/7", req.path)
	}
	if req.key != "node-secret" || req.ts == "" {
		t.Fatalf("上报缺鉴权头: key=%q timestamp=%q", req.key, req.ts)
	}

	// report_id 是面板去重的键，同一批内必须相同且原样送到
	var rows []map[string]interface{}
	if err := json.Unmarshal([]byte(req.body), &rows); err != nil {
		t.Fatalf("上报体不是预期 JSON: %s / %s", err.Error(), req.body)
	}
	if len(rows) != 2 {
		t.Fatalf("上报了 %d 行, want 2", len(rows))
	}
	for _, row := range rows {
		if row["report_id"] != "batch-1" {
			t.Fatalf("行里 report_id = %v, want batch-1（面板靠它拒绝重复入账）", row["report_id"])
		}
	}
}

func TestPostJSONSurfacesPanelFailure(t *testing.T) {
	var got []recorded
	server := newPanel(t, &got, func(recorded) (int, http.Header, string) {
		return okJSON(`{"status":"fail","message":"节点已停用"}`)
	})
	usePanel(t, server)

	// 面板明确回绝时调用方要拿到错误：流量上报据此决定重投哪一批
	err := postJSON("nodeOnline", []*model.NodeOnline{{Uid: 1, IP: "1.2.3.4"}})
	if err == nil || err.Error() != "节点已停用" {
		t.Fatalf("postJSON 错误 = %v, want 节点已停用", err)
	}
}

func TestRetryStopsOnSuccessAndExhausts(t *testing.T) {
	calls := 0
	if err := retry(3, time.Millisecond, func() error {
		calls++
		if calls == 2 {
			return nil
		}
		return http.ErrAbortHandler
	}); err != nil {
		t.Fatalf("第二次成功就该返回 nil, got %v", err)
	}
	if calls != 2 {
		t.Fatalf("重试次数 = %d, want 2（成功即停）", calls)
	}

	calls = 0
	if err := retry(3, time.Millisecond, func() error {
		calls++
		return http.ErrAbortHandler
	}); err == nil {
		t.Fatal("三次都失败必须把错误交回调用方")
	}
	if calls != 3 {
		t.Fatalf("重试次数 = %d, want 3", calls)
	}
}

// 面板的 HTTP 400 同时表示两种完全不同的事：「参数错误」（这条载荷永远不会被接受）与
// 「写库失败」（库整笔回滚，重投就能救回来）。按状态码判会把后者当前者丢掉，
// 所以只有业务码 400200 折成 ErrRejected
func TestPostMarksOnlyParameterErrorAsRejected(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       bool
	}{
		{"参数错误", `{"status":"fail","code":400200,"message":"参数错误"}`, true},
		{"写库失败", `{"status":"fail","code":400201,"message":"上报用户触发审计规则日志失败"}`, false},
		{"反代的错误页没有业务码", `<html><body>400 Bad Request</body></html>`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []recorded
			server := newPanel(t, &got, func(r recorded) (int, http.Header, string) {
				return http.StatusBadRequest, http.Header{}, tc.body
			})
			usePanel(t, server)

			err := PostTrigger(model.Trigger{Uid: 7, Reason: "x.example"})

			if err == nil {
				t.Fatal("400 必须回错误，否则这条会被当成已入账而永久丢失")
			}
			if errors.Is(err, ErrRejected) != tc.want {
				t.Fatalf("ErrRejected = %v, want %v（err: %v）", errors.Is(err, ErrRejected), tc.want, err)
			}
		})
	}
}

// 5xx 与连不上都属「暂时投不出去」，绝不能被打成永久拒绝
func TestPostKeepsServerErrorOutOfRejected(t *testing.T) {
	var got []recorded
	server := newPanel(t, &got, func(r recorded) (int, http.Header, string) {
		return http.StatusServiceUnavailable, http.Header{}, `<html>gateway</html>`
	})
	usePanel(t, server)

	if err := PostTrigger(model.Trigger{Uid: 7, Reason: "x.example"}); err == nil {
		t.Fatal("503 要回错误")
	} else if errors.Is(err, ErrRejected) {
		t.Fatalf("503 不该算永久拒绝: %v", err)
	}
}
