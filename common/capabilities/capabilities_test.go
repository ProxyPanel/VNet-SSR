package capabilities

import (
	"os"
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

	if string(committed) != current {
		t.Fatalf("docs/capabilities.json 已与注册表漂移，请跑：go run ./cmd/capabilities > docs/capabilities.json")
	}
}
