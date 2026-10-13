package log

import (
	"strings"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
)

type capture struct {
	mu     sync.Mutex
	lines  []string
	levels []logrus.Level
}

func (c *capture) Fire(e *logrus.Entry) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lines = append(c.lines, e.Message)
	c.levels = append(c.levels, e.Level)
	return nil
}

func (c *capture) Levels() []logrus.Level { return logrus.AllLevels }

func watch(t *testing.T) *capture {
	t.Helper()
	c := &capture{}
	logrus.AddHook(c)
	return c
}

// 这几个助手在「没有可变参数」时必须走非格式化分支：日志文本里带百分号是常态（命中率、
// 使用率、用户提交的 URL），一旦被当成格式串就会打出 %!X(MISSING)/NOVERB，运维读到的是噪声。
// 判据用 "50%%"：走非格式化分支会原样输出两个百分号，走错分支只剩一个。
func TestMessagesWithoutArgsAreNotFormatted(t *testing.T) {
	c := watch(t)

	Info("命中率 50%%")
	Error("命中率 50%%")
	Warn("命中率 50%%")
	Debug("命中率 50%%")

	if len(c.lines) != 3 {
		t.Fatalf("Debug 在默认级别下不该落一条, 实际收到 %d 条: %v", len(c.lines), c.lines)
	}

	for _, line := range c.lines {
		if line != "命中率 50%%" {
			t.Fatalf("无参日志被格式化过了: %q, want 原样的「命中率 50%%」", line)
		}
		if strings.Contains(line, "NOVERB") || strings.Contains(line, "MISSING") {
			t.Fatalf("日志被当成格式串解析: %q", line)
		}
	}
}

// 有可变参数时仍要走格式化分支，否则 %s 会原样打出来
func TestFormatArgsStillApply(t *testing.T) {
	c := watch(t)

	Info("端口 %d 关闭", 8388)

	if len(c.lines) != 1 || c.lines[0] != "端口 8388 关闭" {
		t.Fatalf("带参日志 = %v, want [端口 8388 关闭]", c.lines)
	}
}

// Err 是错误路径上最常被调到的一句，nil error 也不能让它自己 panic
func TestErrToleratesNilError(t *testing.T) {
	c := watch(t)

	Err(nil)

	if len(c.lines) == 0 || c.lines[0] != "<nil>" {
		t.Fatalf("Err(nil) 的输出 = %v, want [<nil>]", c.lines)
	}
}
