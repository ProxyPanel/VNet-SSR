package main

// 生成 docs/capabilities.json：本后端支持的加密方式/协议/混淆名单。
// 用法：go run ./cmd/capabilities > docs/capabilities.json
// common/capabilities 的测试会拿现场注册表与这个文件比对，名单变了而文件没跟着重生成就会失败。

import (
	"os"

	"github.com/ProxyPanel/VNet-SSR/common/capabilities"
)

func main() {
	out, err := capabilities.JSON()
	if err != nil {
		_, _ = os.Stderr.WriteString(err.Error() + "\n")
		os.Exit(1)
	}

	_, _ = os.Stdout.WriteString(out)
}
