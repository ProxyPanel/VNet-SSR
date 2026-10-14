package cache

import (
	"bytes"
	"runtime"
	"testing"
	"time"
)

func TestCache_Basic(t *testing.T) {
	interval := 200 * time.Millisecond
	ttl := 20 * time.Millisecond
	c := New(interval)
	c.Put("int", 1, ttl)
	c.Put("string", "a", ttl)

	i := c.Get("int")
	if i.(int) != 1 {
		t.Error("should recv 1")
	}

	s := c.Get("string")
	if s.(string) != "a" {
		t.Error("should recv 'a'")
	}
}

func TestCache_TTL(t *testing.T) {
	interval := 200 * time.Millisecond
	ttl := 20 * time.Millisecond
	c := New(interval)
	c.Put("int", 1, ttl)

	i := c.Get("int")
	if i.(int) != 1 {
		t.Error("should recv 1")
	}

	time.Sleep(ttl * 2)
	i = c.Get("int")
	if i != nil {
		t.Error("should recv nil")
	}
}

func TestCache_AutoCleanup(t *testing.T) {
	interval := 10 * time.Millisecond
	ttl := 15 * time.Millisecond
	c := New(interval)
	c.Put("int", 1, ttl)

	time.Sleep(ttl * 2)
	i := c.Get("int")
	if i != nil {
		t.Error("should recv nil")
	}
}

// janitorGoroutines 数的是栈上真在跑的 janitor：NumGoroutine 会被 GC worker 之类的瞬时协程盖住判据
func janitorGoroutines() int {
	buf := make([]byte, 1<<20)
	n := runtime.Stack(buf, true)
	return bytes.Count(buf[:n], []byte("cache.(*janitor).process")) +
		bytes.Count(buf[:n], []byte("cache.(*lruJanitor).process"))
}

func waitJanitors(cond func() bool, timeout time.Duration) bool {
	for deadline := time.Now().Add(timeout); time.Now().Before(deadline); {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// janitor 靠 SetFinalizer 停：缓存不可达之后它必须真的退出，否则每个被丢弃的缓存留下一个协程。
// 新建的协程要先被调度才出现在栈上，所以两头都轮询而不是当场取值
func TestCache_AutoGCStopsJanitor(t *testing.T) {
	const caches = 5
	base := janitorGoroutines()
	holders := make([]*Cache, caches)
	for i := range holders {
		holders[i] = New(10 * time.Millisecond)
		holders[i].Put("int", 1, 15*time.Millisecond)
	}
	if !waitJanitors(func() bool { return janitorGoroutines() >= base+caches }, 2*time.Second) {
		t.Fatalf("每个缓存都该有一个 janitor 协程：base=%d now=%d", base, janitorGoroutines())
	}
	peak := janitorGoroutines()
	for i := range holders {
		holders[i] = nil
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if janitorGoroutines() <= peak-caches {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("janitor 没随缓存回收：peak=%d now=%d", peak, janitorGoroutines())
}
