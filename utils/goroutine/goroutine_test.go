package goroutine

import (
	"errors"
	"testing"
)

// Protect 是 push 服务、UDP 读循环与节点上报协程的兜底：协程里没 recover 的 panic 会终止整个进程，
// 节点表现为「进程没了」而不是「一条连接断了」，systemd 只会看到 Restart=on-failure 的循环
func TestProtectContainsPanicAndReturns(t *testing.T) {
	reached := false
	defer func() {
		if e := recover(); e != nil {
			t.Fatalf("Protect 没兜住 panic，异常漏到了调用方: %v", e)
		}
	}()

	Protect(func() {
		panic(errors.New("协程内的测试 panic"))
	})

	reached = true
	if !reached {
		t.Fatal("Protect 返回后调用方没能继续执行")
	}
}

// 正常路径不能被 Protect 改动语义：函数照常执行完、不吞掉任何东西
func TestProtectRunsTheFunctionToCompletion(t *testing.T) {
	calls := 0
	Protect(func() { calls++ })
	Protect(func() { calls++ })

	if calls != 2 {
		t.Fatalf("被包裹的函数执行了 %d 次, want 2", calls)
	}
}
