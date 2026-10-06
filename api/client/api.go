package client

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/core"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ProxyPanel/VNet-SSR/model"
	"github.com/ProxyPanel/VNet-SSR/utils/langx"
	"github.com/ProxyPanel/VNet-SSR/utils/stringx"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"gopkg.in/resty.v1"
)

var (
	restyc *resty.Client
	// 面板的 WebApiResponse 把 GET payload 哈希进 ETAG 头，带 If-None-Match 且内容未变时直接回 304
	userListEtag string
)

const (
	pullAttempts = 3
	pullBackoff  = 5 * time.Second
)

func init() {
	restyc = resty.New().
		SetTransport(&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}).
		SetTimeout(5 * time.Second).
		SetRedirectPolicy(resty.FlexibleRedirectPolicy(2))
}

// Host 是面板 WebAPI 的基地址；必须由 InitHost 在配置读取完之后写入
// （包初始化时 core 里的 api_host 还是空串，且 Host() 是监听地址，不是面板地址）
var Host = ""

// InitHost 用配置里的 api_host 拼出 WebAPI 基地址
func InitHost() error {
	apiHost := core.GetApp().ApiHost()
	if apiHost == "" {
		return errors.New("api_host is empty, cannot reach the panel")
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
		return "", false, "", errors.Wrap(err, "get request error")
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
		return "", errors.Wrap(err, "get request error")
	}
	if r.StatusCode() != http.StatusOK {
		return "", errors.New(fmt.Sprintf("get request status: %d body: %s", r.StatusCode(), string(r.Body())))
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
			userListEtag = etag
		}

		return nil
	})

	return result, err
}

// SyncUserList 带 If-None-Match 拉一次；unchanged 为 true 表示面板说内容没变，此时 users 不可用
func SyncUserList() (users []*model.UserInfo, unchanged bool, err error) {
	body, changed, etag, err := getWithEtag(userListURL(), userListEtag)
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
		userListEtag = etag
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

func PostAllUserTraffic(allUserTraffic []*model.UserTraffic) error {
	value, err := post(fmt.Sprintf("%s/userTraffic/%s", Host, strconv.Itoa(core.GetApp().NodeId())),
		string(langx.Must(func() (interface{}, error) {
			return json.Marshal(allUserTraffic)
		}).([]byte)))

	if err != nil {
		return err
	}
	if gjson.Get(value, "status").String() != "success" {
		return errors.New(gjson.Get(value, "message").String())
	}
	return nil
}

func PostNodeOnline(nodeOnline []*model.NodeOnline) error {
	value, err := post(fmt.Sprintf("%s/nodeOnline/%s", Host, strconv.Itoa(core.GetApp().NodeId())),
		string(langx.Must(func() (interface{}, error) {
			return json.Marshal(nodeOnline)
		}).([]byte)))

	if err != nil {
		return err
	}

	if gjson.Get(value, "status").String() != "success" {
		return errors.New(stringx.UnicodeToUtf8(gjson.Get(value, "message").String()))
	}
	return nil
}

func PostNodeStatus(status model.NodeStatus) error {
	value, err := post(fmt.Sprintf("%s/nodeStatus/%s", Host, strconv.Itoa(core.GetApp().NodeId())),
		string(langx.Must(func() (interface{}, error) {
			return json.Marshal(status)
		}).([]byte)))

	if err != nil {
		return err
	}
	if gjson.Get(value, "status").String() != "success" {
		return errors.New(stringx.UnicodeToUtf8(gjson.Get(value, "message").String()))
	}
	return nil
}

// PostTrigger when user trigger audit rules then report
func PostTrigger(trigger model.Trigger) error {
	value, err := post(fmt.Sprintf("%s/trigger/%s", Host, strconv.Itoa(core.GetApp().NodeId())),
		string(langx.Must(func() (interface{}, error) {
			return json.Marshal(trigger)
		}).([]byte)))

	if err != nil {
		return err
	}
	if gjson.Get(value, "status").String() != "success" {
		return errors.New(stringx.UnicodeToUtf8(gjson.Get(value, "message").String()))
	}
	return nil
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
