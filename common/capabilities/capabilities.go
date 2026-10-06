// Package capabilities 是本后端「支持哪些算法名」的唯一来源：
// docs/capabilities.json 由 cmd/capabilities 从这里的注册表生成，面板侧的白名单镜像以它为准。
package capabilities

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/ProxyPanel/VNet-SSR/common/ciphers/aead"
	"github.com/ProxyPanel/VNet-SSR/common/ciphers/block"
	"github.com/ProxyPanel/VNet-SSR/common/ciphers/stream"
	"github.com/ProxyPanel/VNet-SSR/common/obfs"
	"github.com/pkg/errors"
)

// 节点侧协议与混淆共用一张注册表，SSR 的语义分组靠这两份名单区分：
// 注册表里出现了新名字而不在这两组内，Current() 会直接报错，不会静默漏掉。
var protocolNames = []string{
	"origin",
	"auth_sha1_v4",
	"auth_aes128_md5",
	"auth_aes128_sha1",
	"auth_chain_a",
	"auth_chain_b",
	"auth_chain_c",
	"auth_chain_d",
	"auth_chain_e",
	"auth_chain_f",
}

var obfsNames = []string{
	"plain",
	"origin",
	"http_simple",
	"http_post",
	"random_head",
	"tls1.2_ticket_auth",
	"tls1.2_ticket_fastauth",
}

type List struct {
	Methods   []string `json:"methods"`
	Protocols []string `json:"protocols"`
	Obfs      []string `json:"obfs"`
}

// Current 从三张加密表与协议/混淆注册表现场取名单；组内升序，便于与已提交的文件做逐字节比较。
func Current() (List, error) {
	l := List{}

	for name := range stream.GetStreamCiphers() {
		l.Methods = append(l.Methods, name)
	}

	for name := range aead.GetAEADCiphers() {
		l.Methods = append(l.Methods, name)
	}

	for name := range block.GetBlockCiphers() {
		l.Methods = append(l.Methods, name)
	}

	registered := map[string]bool{}

	for _, name := range obfs.RegisteredNames() {
		registered[name] = true
	}

	for _, name := range protocolNames {
		if registered[name] {
			l.Protocols = append(l.Protocols, name)
		}
	}

	for _, name := range obfsNames {
		if registered[name] {
			l.Obfs = append(l.Obfs, name)
		}
	}

	// 分组名单之外的注册名必须报错，否则新增的协议/混淆不会出现在 capabilities.json 里
	if extra := ungrouped(l.Protocols, l.Obfs, registered); len(extra) > 0 {
		return l, errors.Errorf("registry names not classified as protocol or obfs: %s", strings.Join(extra, ", "))
	}

	sort.Strings(l.Methods)
	sort.Strings(l.Protocols)
	sort.Strings(l.Obfs)

	if len(l.Methods) == 0 || len(l.Protocols) == 0 || len(l.Obfs) == 0 {
		return l, errors.New("empty capability group; registry lookups are likely not registered yet")
	}

	return l, nil
}

func ungrouped(protocols, obfsList []string, registered map[string]bool) []string {
	known := map[string]bool{}

	for _, name := range protocols {
		known[name] = true
	}

	for _, name := range obfsList {
		known[name] = true
	}

	var extra []string

	for name := range registered {
		if !known[name] {
			extra = append(extra, name)
		}
	}

	sort.Strings(extra)

	return extra
}

// JSON 生成 docs/capabilities.json 的内容。
func JSON() (string, error) {
	l, err := Current()
	if err != nil {
		return "", err
	}

	out, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return "", err
	}

	return string(out) + "\n", nil
}
