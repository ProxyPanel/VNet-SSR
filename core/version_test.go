package core

import (
	"encoding/json"
	"os"
	"testing"
)

// APP_VERSION 与 release/version.json 的 latest 必须相同，deploy.sh 与 upgrade.sh 都拿这两者对版本。
func TestAppVersionMatchesReleaseLatest(t *testing.T) {
	raw, err := os.ReadFile("../release/version.json")
	if err != nil {
		t.Fatalf("读取 release/version.json 失败：%s", err.Error())
	}

	var release struct {
		Latest string `json:"latest"`
	}
	if err := json.Unmarshal(raw, &release); err != nil {
		t.Fatalf("解析 release/version.json 失败：%s", err.Error())
	}

	if release.Latest != APP_VERSION {
		t.Fatalf("core.APP_VERSION=%s 与 release/version.json 的 latest=%s 不一致，发版时两处要一起改（tag 名同为此值）", APP_VERSION, release.Latest)
	}
}
