package network

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestListenerRejectsEmptyAddr(t *testing.T) {
	l := NewListener("", time.Second)

	if err := l.ListenTCP(func(*Request) {}); err == nil {
		t.Error("空地址的 ListenTCP 应该回错误")
	}
	if err := l.ListenUDP(func(*Request) {}); err == nil {
		t.Error("空地址的 ListenUDP 应该回错误")
	}
}

// Close 之后端口必须真的释放：accept 协程没退出的话重载会撞上 address already in use，
// 面板改端口就变成只有重启才生效的操作
func TestListenerCloseReleasesPort(t *testing.T) {
	addr := freeLocalAddr(t)

	l := NewListener(addr, time.Second)
	if err := l.ListenTCP(func(*Request) {}); err != nil {
		t.Fatalf("首次 TCP 监听 %s 失败: %s", addr, err.Error())
	}
	if err := l.ListenUDP(func(*Request) {}); err != nil {
		t.Fatalf("首次 UDP 监听 %s 失败: %s", addr, err.Error())
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close 失败: %s", err.Error())
	}

	again := NewListener(addr, time.Second)
	if err := again.ListenTCP(func(*Request) {}); err != nil {
		t.Fatalf("Close 后同地址仍绑不上: %s", err.Error())
	}
	_ = again.Close()
}

// 单条连接的 handler panic 不能带走监听：recover 挂在每条连接的协程上，
// 少了它一个畸形连接就能让整端口下线（面板侧表现是该账号此后连不上）
func TestConnectionHandlerPanicDoesNotStopListener(t *testing.T) {
	addr := freeLocalAddr(t)
	l := NewListener(addr, 2*time.Second)

	var mu sync.Mutex
	seen := 0
	handled := make(chan struct{}, 4)
	if err := l.ListenTCP(func(request *Request) {
		mu.Lock()
		seen++
		round := seen
		mu.Unlock()

		if round == 1 {
			panic("测试用的连接处理崩溃")
		}
		handled <- struct{}{}
		_ = request.Close()
	}); err != nil {
		t.Fatalf("监听失败: %s", err.Error())
	}
	defer l.Close()

	// 第一条连接：handler 里 panic，必须由 recover 兜住并且不拖垮 accept 循环
	first := dialLocal(t, addr)
	defer first.Close()

	// 第二条连接：只有 accept 循环还活着，handler 才会被再次调用
	second := dialLocal(t, addr)
	defer second.Close()

	select {
	case <-handled:
	case <-time.After(3 * time.Second):
		t.Fatal("第一条连接的 handler panic 之后，监听不再接收新连接")
	}
}

func freeLocalAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	return addr
}

func dialLocal(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("拨入 %s 失败: %s", addr, err.Error())
	}
	return conn
}
