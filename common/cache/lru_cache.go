package cache

import (
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type LRU struct {
	*lrucache
	stopOnce sync.Once
}

type lrucache struct {
	mapping    sync.Map
	lruJanitor *lruJanitor
	TTL        time.Duration
}

type lruelement struct {
	// 到期时间用原子读写：Get 会续期，而缓存本身被多条连接协程与 janitor 同时访问
	expired int64
	Payload interface{}
	TTL     time.Duration
}

func (l *lrucache) Put(key interface{}, payload interface{}) {
	l.mapping.Store(key, &lruelement{
		Payload: payload,
		expired: time.Now().Add(l.TTL).UnixNano(),
		TTL:     l.TTL,
	})
}

func (l *lrucache) Get(key interface{}) interface{} {
	item, exist := l.mapping.Load(key)
	if !exist {
		return nil
	}
	elm := item.(*lruelement)
	now := time.Now()
	if now.UnixNano() > atomic.LoadInt64(&elm.expired) {
		l.mapping.Delete(key)
		return nil
	}
	// 续期只改元素自身的原子字段，不回写 mapping：并发 Clear 之后不能再把旧元素塞回去
	atomic.StoreInt64(&elm.expired, now.Add(elm.TTL).UnixNano())
	return elm.Payload
}

func (l *lrucache) Delete(key interface{}) {
	l.mapping.Delete(key)
}

// Clear 移除全部键：规则集整体换掉时，旧判定必须跟着作废
func (l *lrucache) Clear() {
	l.mapping.Range(func(k, _ interface{}) bool {
		l.mapping.Delete(k)
		return true
	})
}

func (l *lrucache) IsExist(key interface{}) bool {
	_, exist := l.mapping.Load(key)
	return exist
}

func (l *lrucache) First() interface{} {
	var result interface{} = nil
	l.mapping.Range(func(key, value interface{}) bool {
		result = key
		return false
	})
	return result
}

func (l *lrucache) Len() int {
	var result int = 0
	l.mapping.Range(func(key, value interface{}) bool {
		result++
		return true
	})
	return result
}

func (l *lrucache) Clean() {
	now := time.Now().UnixNano()
	l.mapping.Range(func(k, v interface{}) bool {
		// key := k.(string)
		elm := v.(*lruelement)
		if now > atomic.LoadInt64(&elm.expired) {
			l.mapping.Delete(k)
		}
		return true
	})
}

type lruJanitor struct {
	interval time.Duration
	stop     chan struct{}
}

func (j *lruJanitor) process(c *lrucache) {
	ticker := time.NewTicker(j.interval)
	for {
		select {
		case <-ticker.C:
			c.Clean()
		case <-j.stop:
			ticker.Stop()
			return
		}
	}
}

func stopLruJanitor(c *LRU) {
	c.stopOnce.Do(func() { close(c.lruJanitor.stop) })
}

// Stop 立刻停掉 janitor；桶被回收时用它，不能等 finalizer 排到哪次 GC
func (l *LRU) Stop() {
	stopLruJanitor(l)
}

// New return *Cache
func NewLruCache(interval time.Duration) *LRU {
	j := &lruJanitor{
		interval: interval,
		stop:     make(chan struct{}),
	}
	c := &lrucache{
		lruJanitor: j,
		TTL:        interval,
	}
	go j.process(c)
	lru := &LRU{lrucache: c}
	// 终结器只在缓存被回收之后才停 janitor，丢弃缓存不等于立刻停掉那个协程
	runtime.SetFinalizer(lru, stopLruJanitor)
	return lru
}
