package obfs

import "sync"

// UserTable 是单端口模式的密码表：握手在每条连接的协程里读，账号增删在推送协程里写。
// 不能拿裸 map 跨这两侧共享；把锁放在表里，读侧只需一次 RLock。
type UserTable struct {
	mu sync.RWMutex
	m  map[string]string
}

func NewUserTable() *UserTable {
	return &UserTable{m: make(map[string]string)}
}

// Lookup 返回身份对应的密码；没有这个身份时返回空串
func (t *UserTable) Lookup(identity string) string {
	if t == nil {
		return ""
	}
	t.mu.RLock()
	passwd := t.m[identity]
	t.mu.RUnlock()
	return passwd
}

func (t *UserTable) Len() int {
	if t == nil {
		return 0
	}
	t.mu.RLock()
	n := len(t.m)
	t.mu.RUnlock()
	return n
}

func (t *UserTable) Set(identity, passwd string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.m == nil {
		t.m = make(map[string]string)
	}
	t.m[identity] = passwd
	t.mu.Unlock()
}

func (t *UserTable) Delete(identity string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	delete(t.m, identity)
	t.mu.Unlock()
}
