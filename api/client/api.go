package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/core"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ProxyPanel/VNet-SSR/model"
	"github.com/ProxyPanel/VNet-SSR/utils/langx"
	"github.com/ProxyPanel/VNet-SSR/utils/stringx"
	"github.com/go-resty/resty/v2"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

var (
	restyc *resty.Client
	// 面板的 WebApiResponse 把 GET payload 哈希进 ETAG 头，带 If-None-Match 且内容未变时直接回 304
	// 读写分别来自 ReportTask 协程与 NodeReload 的 gin 协程，必须原子存取
	userListEtag atomic.Value // string
)

func loadUserListEtag() string {
	if v, ok := userListEtag.Load().(string); ok {
		return v
	}
	return ""
}

// MarkUserListStale 作废缓存的基线哈希：用户表被 GET 之外的路径改过之后，手里这份哈希
// 描述的已经不是表的内容了。留着它会让下一轮轮询拿旧基线比出「没变」（304），
// 于是推送丢失或面板侧绕过推送的写入都没有收敛机会
func MarkUserListStale() {
	userListEtag.Store("")
}

const (
	pullAttempts = 3
	pullBackoff  = 5 * time.Second

	// panelCodeParameterError 是面板 WebApiResponse 的「参数错误」业务码（HTTP 400200 → 400）。
	// 契约见 docs/openapi.yaml：只有这个码代表载荷永远不可能被接受
	panelCodeParameterError = 400200
)

func init() {
	// 不设 InsecureSkipVerify：跳过证书校验等于任何中间人都能冒充面板，下发用户表与节点配置
	restyc = resty.New().
		SetTimeout(5 * time.Second).
		SetRedirectPolicy(resty.FlexibleRedirectPolicy(2))
}

// Host 是面板 WebAPI 的基地址；必须由 InitHost 在配置读取完之后写入
// （包初始化时 core 里的 api_host 还是空串，且 Host() 是监听地址，不是面板地址）
var Host = ""

// ErrRejected 面板明确说这一条永远不会被接受（业务码 400200）。重投多少次结果都一样，
// 调用方要把它和「暂时投不出去」分开：前者丢弃这一条，后者留着重试
var ErrRejected = errors.New("panel rejected the payload")

// InitHost 用配置里的 api_host 拼出 WebAPI 基地址
func InitHost() error {
	apiHost := core.GetApp().ApiHost()
	if apiHost == "" {
		return errors.New("api_host is empty, cannot reach the panel")
	}
	if !strings.HasPrefix(apiHost, "http://") && !strings.HasPrefix(apiHost, "https://") {
		return errors.New("api_host must start with http:// or https://, got: " + apiHost)
	}

	Host = strings.TrimRight(apiHost, "/") + "/api/ssr/v1"

	return nil
}

// retry 面板不可达时先退避重试：一次抖动不足以让节点退出，也不足以把在线服务打空
func retry(attempts int, wait time.Duration, fn func() error) error {
	var err error

	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}

		if i != attempts-1 {
			time.Sleep(wait)
		}
	}

	return err
}

// implement for vnet api get request
func get(url string) (result string, err error) {
	body, _, _, err := getWithEtag(url, "")
	return body, err
}

// getWithEtag 返回响应体、内容是否变更、面板给的 ETAG；unchanged 为 true 时 body 为空且不是错误
func getWithEtag(url string, etag string) (body string, changed bool, newEtag string, err error) {
	logrus.WithFields(logrus.Fields{"url": url}).Debug("get")

	header := map[string]string{
		"key":       core.GetApp().Key(),
		"timestamp": strconv.FormatInt(time.Now().Unix(), 10),
	}
	if etag != "" {
		header["If-None-Match"] = etag
	}

	r, err := restyc.R().SetHeaders(header).Get(url)
	if err != nil {
		return "", false, "", fmt.Errorf("%s: %w", "get request error", err)
	}
	if r.StatusCode() == http.StatusNotModified { // 内容未变：不是失败，不要按错误重投
		return "", false, "", nil
	}
	if r.StatusCode() != http.StatusOK {
		return "", false, "", errors.New(fmt.Sprintf("get request status: %d body: %s", r.StatusCode(), string(r.Body())))
	}

	return stringx.BUnicodeToUtf8(r.Body()), true, r.Header().Get("Etag"), nil
}

func post(url, param string) (result string, err error) {
	logrus.WithFields(logrus.Fields{
		"param": param,
		"url":   url,
	}).Debug("post")
	header := map[string]string{
		"key":          core.GetApp().Key(),
		"timestamp":    strconv.FormatInt(time.Now().Unix(), 10),
		"Content-Type": "application/json",
	}
	r, err := restyc.R().SetHeaders(header).SetBody(param).Post(url)
	if err != nil {
		return "", fmt.Errorf("%s: %w", "get request error", err)
	}
	if r.StatusCode() != http.StatusOK {
		body := string(r.Body())
		// HTTP 状态分不开永久与暂时：面板的 400 既用于「参数错误」（重投也不会变），也用于「写库失败」
		// （库整笔回滚，重投就能救回来），判据只能取响应体里的业务码
		if gjson.Get(body, "code").Int() == panelCodeParameterError {
			return "", fmt.Errorf("panel rejected: status %d body: %s: %w", r.StatusCode(), body, ErrRejected)
		}
		return "", errors.New(fmt.Sprintf("get request status: %d body: %s", r.StatusCode(), body))
	}
	responseJson := stringx.BUnicodeToUtf8(r.Body())
	return responseJson, nil
}

/*------------------------------ code below is webapi implement ------------------------------*/

func nodeInfoURL() string {
	return fmt.Sprintf("%s/node/%s", Host, strconv.Itoa(core.GetApp().NodeId()))
}

func userListURL() string {
	return fmt.Sprintf("%s/userList/%s", Host, strconv.Itoa(core.GetApp().NodeId()))
}

// GetNodeInfo Get Node Info
func GetNodeInfo() (*model.NodeInfo, error) {
	var result *model.NodeInfo

	err := retry(pullAttempts, pullBackoff, func() error {
		response, err := get(nodeInfoURL())
		if err != nil {
			return err
		}

		info, err := parseNodeInfo(response)
		if err != nil {
			return err
		}

		result = info

		return nil
	})

	return result, err
}

func parseNodeInfo(response string) (*model.NodeInfo, error) {
	if gjson.Get(response, "status").String() != "success" {
		return nil, errors.New(gjson.Get(response, "message").String())
	}
	value := gjson.Get(response, "data").String()
	if value == "" {
		return nil, errors.New("get data not found: " + response)
	}

	result := &model.NodeInfo{}
	if err := json.Unmarshal([]byte(value), result); err != nil {
		return nil, err
	}

	return result, nil
}

// GetUserList 全量拉一次用户列表（启动与重载用），并记下面板的 ETAG 供后续增量判定
func GetUserList() ([]*model.UserInfo, error) {
	var result []*model.UserInfo

	err := retry(pullAttempts, pullBackoff, func() error {
		body, _, etag, err := getWithEtag(userListURL(), "")
		if err != nil {
			return err
		}

		users, err := parseUserList(body)
		if err != nil {
			return err
		}

		result = users
		if etag != "" {
			userListEtag.Store(etag)
		}

		return nil
	})

	return result, err
}

// SyncUserList 带 If-None-Match 拉一次；unchanged 为 true 表示面板说内容没变，此时 users 不可用
func SyncUserList() (users []*model.UserInfo, unchanged bool, err error) {
	body, changed, etag, err := getWithEtag(userListURL(), loadUserListEtag())
	if err != nil {
		return nil, false, err
	}
	if !changed {
		return nil, true, nil
	}

	parsed, err := parseUserList(body)
	if err != nil {
		return nil, false, err
	}
	if etag != "" {
		userListEtag.Store(etag)
	}

	return parsed, false, nil
}

func parseUserList(response string) ([]*model.UserInfo, error) {
	if gjson.Get(response, "status").String() != "success" {
		return nil, errors.New(stringx.UnicodeToUtf8(gjson.Get(response, "message").String()))
	}
	value := gjson.Get(response, "data").String()
	if value == "" {
		return nil, errors.New("get data not found: " + response)
	}

	var result []*model.UserInfo
	if err := json.Unmarshal([]byte(value), &result); err != nil {
		return nil, err
	}

	return result, nil
}

// postJSON 序列化 payload、POST 到带节点 ID 的面板端点，按 envelope 的 status 判成败
func postJSON(path string, payload interface{}) error {
	value, err := post(fmt.Sprintf("%s/%s/%s", Host, path, strconv.Itoa(core.GetApp().NodeId())),
		string(langx.Must(func() (interface{}, error) {
			return json.Marshal(payload)
		}).([]byte)))
	if err != nil {
		return err
	}
	if gjson.Get(value, "status").String() != "success" {
		return errors.New(stringx.UnicodeToUtf8(gjson.Get(value, "message").String()))
	}
	return nil
}

func PostAllUserTraffic(allUserTraffic []*model.UserTraffic) error {
	return postJSON("userTraffic", allUserTraffic)
}

func PostNodeOnline(nodeOnline []*model.NodeOnline) error {
	return postJSON("nodeOnline", nodeOnline)
}

func PostNodeStatus(status model.NodeStatus) error {
	return postJSON("nodeStatus", status)
}

// PostTrigger when user trigger audit rules then report
func PostTrigger(trigger model.Trigger) error {
	return postJSON("trigger", trigger)
}

// GetNodeRule Get Node Rule
func GetNodeRule() (*model.Rule, error) {
	response, err := get(fmt.Sprintf("%s/nodeRule/%s", Host, strconv.Itoa(core.GetApp().NodeId())))
	if err != nil {
		return nil, err
	}
	if gjson.Get(response, "status").String() != "success" {
		return nil, errors.New(stringx.UnicodeToUtf8(gjson.Get(response, "message").String()))
	}
	value := gjson.Get(response, "data").String()
	if value == "" {
		return nil, errors.New("get data not found: " + response)
	}
	result := new(model.Rule)
	err = json.Unmarshal([]byte(value), result)
	if err != nil {
		return nil, err
	}
	return result, nil
}
