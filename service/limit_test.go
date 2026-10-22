package service

import (
	"sync"
	"testing"
	"time"
)

// 单次读取可能大于桶容量：旧实现直接 WaitN(n) 会因超过 burst 报错并完全不限速。
// 这里钉住「超过 burst 时拆成多次等待」而不是回错误
func TestUpLimitChunksAboveBurst(t *testing.T) {
	l := NewLimit()
	l.Set(1, 1000)

	started := time.Now()
	if err := l.UpLimit(1, 2000); err != nil {
		t.Fatalf("超过 burst 的读取不该报错: %s", err.Error())
	}
	if elapsed := time.Since(started); elapsed < 500*time.Millisecond {
		t.Fatalf("2KiB @ 1KiB/s 只用了 %s，限速没有生效", elapsed)
	}
}

// UDP 用非阻塞判据：桶里有令牌才放行；单个数据报大于桶容量时不按超额丢包
func TestAllowUsesNonBlockingTokenBucket(t *testing.T) {
	l := NewLimit()
	l.Set(1, 1000)

	if !l.AllowUp(1, 500) || !l.AllowUp(1, 500) {
		t.Fatal("桶满时的两笔 500 字节都该放行")
	}
	if l.AllowUp(1, 100) {
		t.Fatal("桶已耗尽，100 字节仍被放行")
	}
	if !l.AllowUp(1, 2000) {
		t.Fatal("大于桶容量的单个数据报不该被当成超额丢包")
	}
	if !l.AllowDown(2, 1) {
		t.Fatal("没有限速器的账号应直接放行")
	}
}

// 限速改成 0（不限速）必须把旧限速器摘掉，而不是留着上一档继续卡流量
func TestSetZeroRemovesLimiter(t *testing.T) {
	l := NewLimit()
	l.Set(1, 1024)
	if len(l.upLimits) != 1 || len(l.downLimits) != 1 {
		t.Fatal("Set 没有装上限速器")
	}

	l.Set(1, 0)
	l.gLocker.RLock()
	defer l.gLocker.RUnlock()
	if len(l.upLimits) != 0 || len(l.downLimits) != 0 {
		t.Fatalf("限速改成 0 后仍留有限速器: up=%d down=%d", len(l.upLimits), len(l.downLimits))
	}
}

// 数据面在 UpLimit/DownLimit 里读，推送在 Set/Del 里写；这条用例让 -race job 覆盖同一张表
func TestLimitConcurrentSetAndUse(t *testing.T) {
	l := NewLimit()
	var wg sync.WaitGroup

	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				_ = l.UpLimit(i%4, 0)
				_ = l.DownLimit(i%4, 0)
			}
		}(i)
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 2000; j++ {
				l.Set(i, 1<<20)
				l.Del(i)
			}
		}(i)
	}
	wg.Wait()
}
