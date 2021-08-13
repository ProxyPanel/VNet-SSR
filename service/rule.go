package service

import (
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/api/client"
	"github.com/ProxyPanel/VNet-SSR/common/cache"
	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/model"
	"regexp"
	"time"
)

const (
	RULE_TYPE_REG    = "reg"
	RULE_TYPE_DOMAIN = "domain"
	RULE_TYPE_IP     = "ip"

	RULE_MODE_ALLOW  = "allow"
	RULE_MODE_REJECT = "reject"
	RULE_MODE_ALL    = "all"
)

var (
	ruleServiceInstance = NewRuleService()
)

func GetRuleService() *RuleService {
	return ruleServiceInstance
}

type RuleItemComiled struct {
	model.RuleItem
	compile interface{}
}
type RuleService struct {
	mode  string
	rules []*RuleItemComiled
	cache *cache.LRU
}

func NewRuleService() *RuleService {
	r := new(RuleService)
	r.Reset()
	return r
}

// RuleService set all field to default.
func (r *RuleService) Reset() {
	r.cache = cache.NewLruCache(5 * time.Second)
	r.rules = make([]*RuleItemComiled, 0, 256)
	r.mode = RULE_MODE_ALL
}

func (r *RuleService) LoadFromApi() error {
	rule, err := client.GetNodeRule(core.GetApp().NodeId(), core.GetApp().Key())
	if err != nil {
		return err
	}
	r.Load(rule)
	return nil
}

// RuleService load rule
func (r *RuleService) Load(rule *model.Rule) {
	r.Reset()
	r.mode = rule.Model
	for _, item := range rule.Rules {
		switch item.Type {
		case RULE_TYPE_REG:
			regexCompiled, err := regexp.Compile(item.Pattern)
			if err != nil {
				log.Error("compile regex %s error: %s ", item.Pattern, err.Error())
				continue
			}

			r.rules = append(r.rules, &RuleItemComiled{
				RuleItem: item,
				compile:  regexCompiled,
			})
		case RULE_TYPE_IP:
			r.rules = append(r.rules, &RuleItemComiled{
				RuleItem: item,
				compile:  item.Pattern,
			})
		case RULE_TYPE_DOMAIN:
			r.rules = append(r.rules, &RuleItemComiled{
				RuleItem: item,
				compile:  item.Pattern,
			})
		}
	}
	log.Info("loaded rule set: %+v", *rule)
}

func (r *RuleService) JudgeHostWithReport(ipOrDomain string, port int) bool {
	ruleId, result, isFromCache := r.judgeWithCache(ipOrDomain, port)

	if isFromCache {
		return result
	}

	uid := GetSSRManager().PortToUid(port)
	if !result {
		go func() {
			err := client.PostTrigger(core.GetApp().NodeId(), core.GetApp().Key(), model.Trigger{
				Uid:    uid,
				RuleId: ruleId,
				Reason: ipOrDomain,
			})
			if err != nil {
				log.Err(err)
			}
		}()
	}
	return result
}

// add cache because this function has a lot invoke
func (r *RuleService) judgeWithCache(ipOrDomain string, port int) (ruleId int, result bool, isFromCache bool) {
	cacheKey := fmt.Sprintf("%s:%v", ipOrDomain, port)
	value, isFromCache := r.cache.Get(cacheKey).(struct {
		RuleId int
		Result bool
	})

	if isFromCache {
		return value.RuleId, value.Result, isFromCache
	}

	ruleId, result = r.judge(ipOrDomain)

	r.cache.Put(cacheKey, struct {
		RuleId int
		Result bool
	}{
		ruleId, result,
	})

	return ruleId, result, isFromCache
}

func (r *RuleService) judge(host string) (int, bool) {
	// check if cache have value then return cache value
	if r.mode == RULE_MODE_ALL {
		return 0, true
	}

	for _, regexItem := range r.rules {
		switch regexItem.Type {
		case RULE_TYPE_REG:
			regexCompiled, ok := regexItem.compile.(*regexp.Regexp)
			if !ok {
				log.Error("regex %s break", regexItem.Pattern)
				continue
			}

			if r.mode == RULE_MODE_ALLOW && regexCompiled.Match([]byte(host)) {
				return 0, true
			}

			if r.mode == RULE_MODE_REJECT && regexCompiled.Match([]byte(host)) {
				return regexItem.Id, false
			}

		case RULE_TYPE_DOMAIN, RULE_TYPE_IP:
			if r.mode == RULE_MODE_ALLOW && regexItem.Pattern == host {
				return 0, true
			}

			if r.mode == RULE_MODE_REJECT && regexItem.Pattern == host {
				return regexItem.Id, false
			}
		default:
			continue
		}
	}

	if r.mode == RULE_MODE_REJECT {
		return 0, true
	}
	return 0, false
}
