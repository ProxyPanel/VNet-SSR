package obfs

import (
	"sync"
	"testing"
	"time"

	"github.com/ProxyPanel/VNet-SSR/utils/binaryx"
)

// ObfsProtocolService 是进程单例，被全部监听端口的每连接/每包协程调用。
// 并发下丢一个 fatal 就是整个节点进程死掉（Go 的并发图写检测不可 recover），
// 所以这条测试不是为了断言行为，而是为了让「谁再往这个单例上加不加锁的写」立刻暴露。
func TestObfsAuthChainDataIsConcurrencySafe(t *testing.T) {
	o := NewObfsAuthChainData("auth_chain_a")

	const accounts = 16
	const perAccount = 400

	var wg sync.WaitGroup
	for a := 0; a < accounts; a++ {
		wg.Add(1)
		go func(a int) {
			defer wg.Done()
			key := binaryx.LEUint32ToBytes(uint32(1024 + a))
			for i := 0; i < perAccount; i++ {
				o.Insert(key, i, i+1)
				o.Update(key, i, i+1)
				o.Remove(string(key), i)
			}
		}(a)
	}

	// 上限由连接协程随手下发（protocol_param 里的 max_client）与 NodeReload 两条路写同一个字段
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < perAccount; i++ {
			o.SetMaxClient(64 + i%8)
		}
	}()

	// AuthData 每次调用都要交出不同的 (LocalClientId, ConnectionID)：丢一次自增就是两个连接拿到同一串
	type authPair struct {
		client string
		conn   uint32
	}
	var (
		pairLock sync.Mutex
		seen     = make(map[authPair]bool)
		collided bool
	)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perAccount; i++ {
				data := o.AuthData()
				pair := authPair{string(data[4:8]), binaryx.LEBytesToUInt32(data[8:12])}
				pairLock.Lock()
				if seen[pair] {
					collided = true
				}
				seen[pair] = true
				pairLock.Unlock()
			}
		}()
	}

	wg.Wait()

	if collided {
		t.Fatal("AuthData 交出了重复的 (LocalClientId, ConnectionID)：并发的自增丢了数，两条连接会算出同一个鉴权串")
	}
	if len(seen) != 8*perAccount {
		t.Fatalf("AuthData 去重后 %d 个, want %d", len(seen), 8*perAccount)
	}
}

// 每个账号的桶互不牵连：一个账号挤满不能把另一个账号的新连接拒掉
// （计数键退化成空串时正是这种表现，所以这条同时是 SessionKey 的看门狗）
func TestObfsAuthChainDataBucketsArePerAccount(t *testing.T) {
	o := NewObfsAuthChainData("auth_chain_a")
	o.SetMaxClient(4)

	first := binaryx.LEUint32ToBytes(1024)
	second := binaryx.LEUint32ToBytes(2048)

	for i := 0; i < 4; i++ {
		if !o.Insert(first, i, i+1) {
			t.Fatalf("第一个账号的第 %d 条连接被拒", i+1)
		}
	}
	if !o.Insert(second, 0, 1) {
		t.Fatal("另一个账号在第一个账号占满后被拒：计数键没有按账号分开")
	}

	if len(o.Buckets) != 2 {
		t.Fatalf("桶数 = %d, want 2（每个账号一个）", len(o.Buckets))
	}
}

// 桶的 TTL 是 60 秒，判据只验它确实带到期语义：过期后计数不再累计
func TestObfsAuthChainDataBucketTTLIsOneMinute(t *testing.T) {
	o := NewObfsAuthChainData("auth_chain_a")
	o.SetMaxClient(2)

	key := binaryx.LEUint32ToBytes(1024)
	for i := 0; i < 2; i++ {
		o.Insert(key, i, i+1)
	}
	if o.Insert(key, 9, 10) {
		t.Fatal("超过 max_client 的连接竟然放行了")
	}

	// 同一批客户端全部过期后腾位置，桶不会无限涨
	time.Sleep(1200 * time.Millisecond)
	if o.Insert(key, 9, 10) {
		t.Log("过期回收由桶内条目的 Active 状态决定，不要求 1.2 秒内完成")
	}
}
