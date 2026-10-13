package service

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ProxyPanel/VNet-SSR/api/client"
	"github.com/ProxyPanel/VNet-SSR/common/cache"
	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/model"
	"github.com/ProxyPanel/VNet-SSR/utils/goroutine"
)

const (
	RuleTypeReg    = "reg"
	RuleTypeDomain = "domain"
	RuleTypeIp     = "ip"

	RuleModeAllow  = "allow"
	RuleModeReject = "reject"
	RuleModeAll    = "all"
)

var (
	ruleServiceInstance = NewRuleService()
)

func GetRuleService() *RuleService {
	return ruleServiceInstance
}

// domainRule 精确域名或 *.example.com 通配后缀（含 example.com 本身）
type domainRule struct {
	base     string
	wildcard bool
}

func (d *domainRule) match(host string) bool {
	if !d.wildcard {
		return host == d.base
	}
	return host == d.base || strings.HasSuffix(host, "."+d.base)
}

// ipRule 单 IP 精确匹配，或 10.0.0.0/8 形式的网段匹配
type ipRule struct {
	cidr *net.IPNet
	ip   string
}

func (i *ipRule) match(host string) bool {
	if i.cidr != nil {
		ip := net.ParseIP(host)
		return ip != nil && i.cidr.Contains(ip)
	}
	return host == i.ip
}

type RuleItemCompiled struct {
	model.RuleItem
	compile interface{}
}

type RuleService struct {
	// 规则集在启动/重载/周期刷新时整体替换，判定在每条连接的协程里读
	mu    sync.RWMutex
	mode  string
	rules []*RuleItemCompiled
	// cache 按 host 缓存判定结果；reports 按 (host,identity) 抑制重复上报——
	// 两者必须分开：判定与账号无关，上报却按账号记账
	cache    *cache.LRU
	reports  *cache.LRU
	triggers *triggerQueue
}

func NewRuleService() *RuleService {
	return &RuleService{
		cache:    cache.NewLruCache(5 * time.Second),
		reports:  cache.NewLruCache(5 * time.Minute),
		rules:    make([]*RuleItemCompiled, 0, 256),
		mode:     RuleModeAll,
		triggers: newTriggerQueue(),
	}
}

func (r *RuleService) LoadFromApi() error {
	rule, err := client.GetNodeRule()
	if err != nil {
		return err
	}
	r.Load(rule)
	return nil
}

// Load 编译并原子换入新规则集，同时清空判定缓存
func (r *RuleService) Load(rule *model.Rule) {
	compiled := make([]*RuleItemCompiled, 0, len(rule.Rules))
	for _, item := range rule.Rules {
		switch item.Type {
		case RuleTypeReg:
			regexCompiled, err := regexp.Compile(item.Pattern)
			if err != nil {
				log.Error("compile regex %s error: %s ", item.Pattern, err.Error())
				continue
			}
			compiled = append(compiled, &RuleItemCompiled{RuleItem: item, compile: regexCompiled})

		case RuleTypeDomain:
			wildcard := strings.HasPrefix(item.Pattern, "*.")
			base := strings.ToLower(strings.TrimPrefix(item.Pattern, "*."))
			if base == "" {
				log.Error("domain rule %s has empty base, skip", item.Pattern)
				continue
			}
			compiled = append(compiled, &RuleItemCompiled{RuleItem: item, compile: &domainRule{base: base, wildcard: wildcard}})

		case RuleTypeIp:
			if strings.Contains(item.Pattern, "/") {
				_, ipNet, err := net.ParseCIDR(item.Pattern)
				if err != nil {
					log.Error("parse cidr %s error: %s", item.Pattern, err.Error())
					continue
				}
				compiled = append(compiled, &RuleItemCompiled{RuleItem: item, compile: &ipRule{cidr: ipNet}})
			} else {
				compiled = append(compiled, &RuleItemCompiled{RuleItem: item, compile: &ipRule{ip: item.Pattern}})
			}
		}
	}

	r.mu.Lock()
	r.mode = rule.Model
	r.rules = compiled
	r.mu.Unlock()
	// 旧规则下的判定与上报去重都即刻作废：规则换了一轮，违规该重新报
	r.cache.Clear()
	r.reports.Clear()
	log.Info("loaded rule set: mode %s, %d rules", rule.Model, len(compiled))
}

func (r *RuleService) JudgeHostWithReport(ipOrDomain string, identity int, ev core.AuditContext) bool {
	ruleId, result := r.judgeCached(ipOrDomain)

	if result {
		return true
	}

	// 被拒就上报，但同一 (host,identity) 在窗口内只报一次；持续撞墙的会话安静下来 5 分钟后才会再报
	if !r.shouldReport(ipOrDomain, identity) {
		return false
	}

	uid := GetSSRManager().IdentityToUid(identity)
	if uid == 0 {
		// 反查不到账号的上报面板必拒（exists:user），入队只会永久堵住重投队列
		log.Error("trigger for unknown identity %v dropped: %s", identity, ipOrDomain)
		return false
	}
	r.triggers.push(model.Trigger{
		Uid:           uid,
		RuleId:        ruleId,
		Reason:        cutBytes(ipOrDomain, 255),
		Target:        cutBytes(ev.Target, 255),
		SniffProtocol: ev.SniffProtocol,
		SniffHost:     cutBytes(ev.SniffHost, 255),
		SniffUri:      cutBytes(ev.SniffUri, 1024),
	})
	return false
}

// cutBytes 按面板侧 max 校验截断（越界整条会被拒收变毒丸）；不在多字节字符中间切断
func cutBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	b := []byte(s[:max])
	for len(b) > 0 && b[len(b)-1]&0xC0 == 0x80 { // 回退掉续字节
		b = b[:len(b)-1]
	}
	if len(b) > 0 && b[len(b)-1]&0x80 != 0 { // 丢掉被截断序列的首字节
		b = b[:len(b)-1]
	}
	return string(b)
}

// triggerQueue 让违规上报活过面板的网络波动与临时下线：入队即返回（不拖慢连接），
// 发送失败留在队列按拍重试，面板恢复后补发。面板侧按认领键去重，重投不会产生第二条记录
type triggerQueue struct {
	mu      sync.Mutex
	pending []model.Trigger
	wake    chan struct{}
}

func newTriggerQueue() *triggerQueue {
	q := &triggerQueue{wake: make(chan struct{}, 1)}
	go goroutine.Protect(q.loop)
	return q
}

func (q *triggerQueue) push(t model.Trigger) {
	q.mu.Lock()
	// 队列满丢最旧：新违规比旧的更值得告警，且总账有 rule_log 上限约束
	if len(q.pending) >= 1024 {
		q.pending = append(q.pending[1:], t)
	} else {
		q.pending = append(q.pending, t)
	}
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *triggerQueue) loop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-q.wake:
		case <-ticker.C:
		}
		q.drain()
	}
}

func (q *triggerQueue) drain() {
	for {
		q.mu.Lock()
		if len(q.pending) == 0 {
			q.mu.Unlock()
			return
		}
		head := q.pending[0]
		q.mu.Unlock()

		if err := client.PostTrigger(head); err != nil {
			log.Err(err) // 留在队首，下一拍重试；顺序保持，先违的规先入账
			return
		}

		q.mu.Lock()
		if len(q.pending) > 0 {
			q.pending = q.pending[1:]
		}
		q.mu.Unlock()
	}
}

// judgeResult 是判定缓存的值类型
type judgeResult struct {
	RuleId int
	Result bool
}

// judgeCached 判定只与 host 有关，缓存键不含 identity：同一被拒域名的每个账号都会各自走到上报判据
func (r *RuleService) judgeCached(host string) (ruleId int, result bool) {
	if cached, fromCache := r.cache.Get(host).(judgeResult); fromCache {
		return cached.RuleId, cached.Result
	}

	ruleId, result = r.judge(host)

	r.cache.Put(host, judgeResult{RuleId: ruleId, Result: result})

	return ruleId, result
}

// shouldReport 是 (host,identity) 维度的上报去重；LRU 的 Get 会续期，
// 持续撞墙等于一次上报，安静满 5 分钟才会再报一次
func (r *RuleService) shouldReport(host string, identity int) bool {
	key := fmt.Sprintf("%s:%v", host, identity)
	if _, reported := r.reports.Get(key).(bool); reported {
		return false
	}
	r.reports.Put(key, true)
	return true
}

func (r *RuleService) judge(host string) (int, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.mode == RuleModeAll {
		return 0, true
	}

	lower := strings.ToLower(host)
	for _, ruleItem := range r.rules {
		matched := false
		switch m := ruleItem.compile.(type) {
		case *regexp.Regexp:
			matched = m.MatchString(host)
		case *domainRule:
			matched = m.match(lower)
		case *ipRule:
			matched = m.match(lower)
		}
		if !matched {
			continue
		}
		if r.mode == RuleModeAllow {
			return 0, true
		}
		if r.mode == RuleModeReject {
			return ruleItem.Id, false
		}
	}

	if r.mode == RuleModeReject {
		return 0, true
	}
	return 0, false
}
