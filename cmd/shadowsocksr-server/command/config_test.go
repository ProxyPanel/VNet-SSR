package command

import (
	"testing"

	"github.com/spf13/viper"
)

// 启动前的必填判据：这几项缺任何一项都不该往下走——api_host 为空会让每个请求带着无 host 的 URL
// 发出并当场退出，node_id 为 0 会被拼成 /node/0 去要一个不存在的节点，key 空则每个请求都被面板拒。
// 注意 node_id 用的是「0 即未填」的判据，所以面板上的 0 号节点本来就用不了。
func TestCheckRequiredGatesStartupConfig(t *testing.T) {
	complete := map[string]interface{}{
		API_HOST: "https://panel.example.com",
		HOST:     "0.0.0.0",
		NODE_ID:  7,
		KEY:      "node-secret",
	}

	restore := func() {
		for _, item := range flagConfigs {
			viper.Set(item.Name, item.Default)
		}
	}
	for name, value := range complete {
		viper.Set(name, value)
	}
	t.Cleanup(restore)

	if !checkRequired() {
		t.Fatal("四项齐全时应该放行")
	}

	for _, missing := range []string{API_HOST, HOST, KEY} {
		restore()
		for name, value := range complete {
			viper.Set(name, value)
		}
		viper.Set(missing, "")
		if checkRequired() {
			t.Fatalf("%s 为空时仍然放行", missing)
		}
	}

	// node_id 的判据是 0 视为未填
	for _, value := range []int{0} {
		restore()
		for name, item := range complete {
			viper.Set(name, item)
		}
		viper.Set(NODE_ID, value)
		if checkRequired() {
			t.Fatalf("node_id = %d 时仍然放行", value)
		}
	}
}

// flagConfigs 是命令行标志与必填判据的唯一来源：加一项而忘了判据，就等于让它静默可选
func TestFlagConfigsCoverEveryDocumentedKey(t *testing.T) {
	want := map[string]bool{API_HOST: true, HOST: true, NODE_ID: true, KEY: true}
	got := make(map[string]bool, len(flagConfigs))

	for _, item := range flagConfigs {
		got[item.Name] = true
		if item.Usage == "" {
			t.Fatalf("%s 没有 Usage，--help 上会是空白", item.Name)
		}
	}

	for name := range want {
		if !got[name] {
			t.Fatalf("配置项 %s 不在 flagConfigs 里，读配置与必填判据都不会管它", name)
		}
	}
}
