package client

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/core"
	"net/http"
	"strconv"
	"time"

	"github.com/ProxyPanel/VNet-SSR/model"
	"github.com/ProxyPanel/VNet-SSR/utils/langx"
	"github.com/ProxyPanel/VNet-SSR/utils/stringx"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"gopkg.in/resty.v1"
)

var restyc *resty.Client

func init() {
	restyc = resty.New().
		SetTransport(&http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}).
		SetTimeout(5 * time.Second).
		SetRedirectPolicy(resty.FlexibleRedirectPolicy(2))
}

var Host = core.GetApp().Host() + "/api/ssr/v1"

// implement for vnet api get request
func get(url string) (result string, err error) {
	logrus.WithFields(logrus.Fields{"url": url}).Debug("get")

	header := map[string]string{
		"key":       core.GetApp().Key(),
		"timestamp": strconv.FormatInt(time.Now().Unix(), 10),
	}
	r, err := restyc.R().SetHeaders(header).Get(url)
	if err != nil {
		return "", errors.Wrap(err, "get request error")
	}
	if r.StatusCode() != http.StatusOK {
		return "", errors.New(fmt.Sprintf("get request status: %d body: %s", r.StatusCode(), string(r.Body())))
	}
	body := r.Body()
	responseJson := stringx.BUnicodeToUtf8(body)

	return responseJson, nil
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

// GetNodeInfo Get Node Info
func GetNodeInfo() (*model.NodeInfo, error) {
	response, err := get(fmt.Sprintf("%s/node/%s", Host, strconv.Itoa(core.GetApp().NodeId())))
	if err != nil {
		return nil, err
	}

	if gjson.Get(response, "status").String() != "success" {
		return nil, errors.New(gjson.Get(response, "message").String())
	}
	value := gjson.Get(response, "data").String()
	if value == "" {
		return nil, errors.New("get data not found: " + response)
	}
	result := &model.NodeInfo{}
	err = json.Unmarshal([]byte(value), &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// GetUserList Get User List
func GetUserList() ([]*model.UserInfo, error) {
	response, err := get(fmt.Sprintf("%s/userList/%s", Host, strconv.Itoa(core.GetApp().NodeId())))
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
	var result []*model.UserInfo
	err = json.Unmarshal([]byte(value), &result)
	if err != nil {
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
