package service

import (
	"testing"

	"github.com/ProxyPanel/VNet-SSR/model"
)

// 面板自带规则（database/seeders/RuleSeeder.php 的 18 条，逐条抄录）。
// Go RE2 拒绝前瞻/反向引用等构造，编译失败会被 Load 静默跳过——这里钉住「全部可编译 + 抽样判定正确」，
// 面板侧同步用 RuleRequest::re2Compatible 挡不兼容写法，两边共同保证内置规则在 VNET 节点真实生效。
func TestPanelBuiltinRulesCompileAndMatch(t *testing.T) {
	patterns := []string{
		`(.*.||)(^360|0360|1360|3600|360safe|^so|qhimg|qhmsg|^yunpan|qihoo|qhcdn|qhupdate|360totalsecurity|360shouji|qihucdn|360kan|secmp).(cn|com|net)`,
		`(.guanjia.qq.com|qqpcmgr|QQPCMGR)`,
		`(.*.||)(rising|kingsoft|duba|xindubawukong|jinshanduba).(com|net|org)`,
		`(.*.||)(netvigator|torproject).(cn|com|net|org)`,
		`(api|ps|sv|offnavi|newvector|ulog.imap|newloc|tracknavi)(.map|).(baidu|n.shifen).com`,
		`(.*.||)(dafahao|minghui|dongtaiwang|dajiyuan|falundata|shenyun|tuidang|epochweekly|epochtimes|ntdtv|falundafa|wujieliulan|zhengjian).(org|com|net)`,
		`(torrent|.torrent|peer_id=|info_hash|get_peers|find_node|BitTorrent|announce_peer|announce.php?passkey=)`,
		`((^.*@)(guerrillamail|guerrillamailblock|sharklasers|grr|pokemail|spam4|bccto|chacuo|027168).(info|biz|com|de|net|org|me|la)|Subject|HELO|SMTP)`,
		`(.?)(xunlei|sandai|Thunder|XLLiveUD)(.)`,
		`(.*.||)(baidu|qq|163|189|10000|10010|10086|sohu|sogoucdn|sogou|uc|58|taobao|qpic|bilibili|hdslb|acgvideo|sina|douban|doubanio|xiaohongshu|sinaimg|weibo|xiaomi|youzanyun|meituan|dianping|biliapi|huawei|pinduoduo|cnzz).(org|com|net|cn)`,
		`(.*.||)(icbc|ccb|boc|bankcomm|abchina|cmbchina|psbc|cebbank|cmbc|pingan|spdb|citicbank|cib|hxb|bankofbeijing|hsbank|tccb|4001961200|bosc|hkbchina|njcb|nbcb|lj-bank|bjrcb|jsbchina|gzcb|cqcbank|czbank|hzbank|srcb|cbhb|cqrcb|grcbank|qdccb|bocd|hrbcb|jlbank|bankofdl|qlbchina|dongguanbank|cscb|hebbank|drcbank|zzbank|bsb|xmccb|hljrcc|jxnxs|gsrcu|fjnx|sxnxs|gx966888|zj96596|hnnxs|ahrcu|shanxinj|hainanbank|scrcu|gdrcu|hbxh|ynrcc|lnrcc|nmgnxs|hebnx|jlnls|js96008|hnnx|sdnxs).(org|com|net|cn)`,
		`(.*.||)(firstbank|bot|cotabank|megabank|tcb-bank|landbank|hncb|bankchb|tbb|ktb|tcbbank|scsb|bop|sunnybank|kgibank|fubon|ctbcbank|cathaybk|eximbank|bok|ubot|feib|yuantabank|sinopac|esunbank|taishinbank|jihsunbank|entiebank|hwataibank|csc|skbank).(org|com|net|tw)`,
		`(.*.||)(alipay|baifubao|yeepay|99bill|95516|51credit|cmpay|tenpay|lakala|jdpay).(org|com|net|cn)`,
		`(.*.||)(visa|mycard|mastercard|gov|gash|beanfun|bank|line).(org|com|net|cn|tw|jp|kr)`,
		`(.*.||)(shenzhoufilm|secretchina|renminbao|aboluowang|mhradio|guangming|zhengwunet|soundofhope|yuanming|zhuichaguoji|fgmtv|xinsheng|shenyunperformingarts|epochweekly|tuidang|shenyun|falundata|bannedbook|pincong|rfi|mingjingnews|boxun|rfa|scmp|ogate|voachinese).(org|com|net|rocks|fr)`,
		`(.*.||)(youtube|googlevideo|hulu|netflix|nflxvideo|akamai|nflximg|hbo|mtv|bbc|tvb).(org|club|com|net|tv)`,
		`(.*.||)(fast|speedtest).(org|com|net|cn)`,
		`(.*.||)(metatrader4|metatrader5|mql5).(org|com|net)`,
	}

	rule := &model.Rule{Model: RuleModeReject}
	for i, p := range patterns {
		rule.Rules = append(rule.Rules, model.RuleItem{Id: i + 1, Type: RuleTypeReg, Pattern: p})
	}
	GetRuleService().Load(rule)

	if len(GetRuleService().rules) != len(patterns) {
		t.Fatalf("18 条内置规则必须全部编译进规则集，实际 %d 条（有 pattern 被 RE2 拒了）", len(GetRuleService().rules))
	}

	cases := []struct {
		host  string
		allow bool
	}{
		{"www.bilibili.com", false},  // 大陆应用
		{"api.map.baidu.com", false}, // 百度定位
		{"a.torproject.org", false},  // 暗网相关
		{"download.torrent", false},  // BT 扩展名
		{"www.speedtest.net", false}, // 测速类
		{"www.alipay.com", false},    // 第三方支付
		{"mql5.com", false},          // 外汇交易
		{"google.com", true},         // 名单外放行
		{"github.com", true},         // 不含被禁子串
	}
	for _, c := range cases {
		if _, ok := GetRuleService().judgeCached(c.host); ok != c.allow {
			t.Errorf("%s: got allow=%v want %v", c.host, !ok, c.allow)
		}
	}
}
