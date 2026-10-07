package capabilities

import (
	"os"
	"strings"
	"testing"
)

// docs/capabilities.json 是面板侧白名单的对照来源，必须与现场注册表一致：
// 改了实现（增删算法）却没重生成文件，这条会失败。
func TestCommittedCapabilitiesMatchesTheRegistry(t *testing.T) {
	committed, err := os.ReadFile("../../docs/capabilities.json")
	if err != nil {
		t.Fatalf("读取 docs/capabilities.json 失败：%s", err.Error())
	}

	current, err := JSON()
	if err != nil {
		t.Fatalf("从注册表生成名单失败：%s", err.Error())
	}

	// 仓库里存的是 LF，Windows 上 checkout 常带 core.autocrlf=true 变成 CRLF：
	// 行尾不是这份文件要钉住的内容，比之前先归一化
	if strings.ReplaceAll(string(committed), "\r\n", "\n") != current {
		t.Fatalf("docs/capabilities.json 已与注册表漂移，请跑：go run ./cmd/capabilities > docs/capabilities.json")
	}
}
