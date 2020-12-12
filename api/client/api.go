package client

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/pkg/errors"
	"github.com/rc452860/vnet/model"
	"github.com/rc452860/vnet/utils/langx"
	"github.com/rc452860/vnet/utils/stringx"
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

var (
	HOST = ""
)

func SetHost(host string) {
	HOST = host
}

// implement for vnet api get request
func get(url string, header map[string]string) (result string, err error) {
	logrus.WithFields(logrus.Fields{
		"url": url,
	}).Debug("get")

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

func post(url, param string, header map[string]string) (result string, err error) {
	logrus.WithFields(logrus.Fields{
		"param": param,
		"url":   url,
	}).Debug("post")
	header["Content-Type"] = "application/json"
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

// GetNodeInfo
func GetNodeInfo(nodeID int, key string) (*model.NodeInfo, error) {
	response, err := get(fmt.Sprintf("%s/api/web/v1/node/%s", HOST, strconv.Itoa(nodeID)), map[string]string{
		"key":       key,
		"timestamp": strconv.FormatInt(time.Now().Unix(), 10),
	})
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

// GetUserList
func GetUserList(nodeID int, key string) ([]*model.UserInfo, error) {
	response, err := get(fmt.Sprintf("%s/api/web/v1/userList/%s", HOST, strconv.Itoa(nodeID)), map[string]string{
		"key":       key,
		"timestamp": strconv.FormatInt(time.Now().Unix(), 10),
	})
	if err != nil {
		return nil, err
	}
	if gjson.Get(response, "status").String() != "success" {
		return nil, errors.New((stringx.UnicodeToUtf8(gjson.Get(response, "message").String())))
	}
	value := gjson.Get(response, "data").String()
	if value == "" {
		return nil, errors.New("get data not found: " + response)
	}
	result := []*model.UserInfo{}
	err = json.Unmarshal([]byte(value), &result)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func PostAllUserTraffic(allUserTraffic []*model.UserTraffic, nodeID int, key string) error {
	value, err := post(fmt.Sprintf("%s/api/web/v1/userTraffic/%s", HOST, strconv.Itoa(nodeID)),
		string(langx.Must(func() (interface{}, error) {
			return json.Marshal(allUserTraffic)
		}).([]byte)),
		map[string]string{
			"key":       key,
			"timestamp": strconv.FormatInt(time.Now().Unix(), 10),
		})

	if err != nil {
		return err
	}
	if gjson.Get(value, "status").String() != "success" {
		return errors.New(gjson.Get(value, "message").String())
	}
	return nil
}

func PostNodeOnline(nodeOnline []*model.NodeOnline, nodeID int, key string) error {
	value, err := post(fmt.Sprintf("%s/api/web/v1/nodeOnline/%s", HOST, strconv.Itoa(nodeID)),
		string(langx.Must(func() (interface{}, error) {
			return json.Marshal(nodeOnline)
		}).([]byte)),
		map[string]string{
			"key":       key,
			"timestamp": strconv.FormatInt(time.Now().Unix(), 10),
		})

	if err != nil {
		return err
	}

	if gjson.Get(value, "status").String() != "success" {
		return errors.New(stringx.UnicodeToUtf8(gjson.Get(value, "message").String()))
	}
	return nil
}

func PostNodeStatus(status model.NodeStatus, nodeID int, key string) error {
	value, err := post(fmt.Sprintf("%s/api/web/v1/nodeStatus/%s", HOST, strconv.Itoa(nodeID)),
		string(langx.Must(func() (interface{}, error) {
			return json.Marshal(status)
		}).([]byte)),
		map[string]string{
			"key":       key,
			"timestamp": strconv.FormatInt(time.Now().Unix(), 10),
		})

	if err != nil {
		return err
	}
	if gjson.Get(value, "status").String() != "success" {
		return errors.New((stringx.UnicodeToUtf8(gjson.Get(value, "message").String())))
	}
	return nil
}

// when user trigger audit rules then report
func PostTrigger(nodeID int, key string, trigger model.Trigger) error {
	value, err := post(fmt.Sprintf("%s/api/web/v1/trigger/%s", HOST, strconv.Itoa(nodeID)),
		string(langx.Must(func() (interface{}, error) {
			return json.Marshal(trigger)
		}).([]byte)),
		map[string]string{
			"key":       key,
			"timestamp": strconv.FormatInt(time.Now().Unix(), 10),
		})

	if err != nil {
		return err
	}
	if gjson.Get(value, "status").String() != "success" {
		return errors.New((stringx.UnicodeToUtf8(gjson.Get(value, "message").String())))
	}
	return nil
}

// GetNodeRule
func GetNodeRule(nodeID int, key string) (*model.Rule, error) {
	response, err := get(fmt.Sprintf("%s/api/web/v1/nodeRule/%s", HOST, strconv.Itoa(nodeID)), map[string]string{
		"key":       key,
		"timestamp": strconv.FormatInt(time.Now().Unix(), 10),
	})
	if err != nil {
		return nil, err
	}
	if gjson.Get(response, "status").String() != "success" {
		return nil, errors.New((stringx.UnicodeToUtf8(gjson.Get(response, "message").String())))
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
