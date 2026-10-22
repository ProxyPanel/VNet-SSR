package obfs

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"github.com/ProxyPanel/VNet-SSR/utils/binaryx"
	"github.com/ProxyPanel/VNet-SSR/utils/bytesx"
	"github.com/ProxyPanel/VNet-SSR/utils/randomx"
	"hash"
	"sync"
	"time"

	"github.com/ProxyPanel/VNet-SSR/common/cache"
	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/utils/goroutine"
)

func conbineToBytes(data ...interface{}) []byte {
	buf := new(bytes.Buffer)
	for _, item := range data {
		binary.Write(buf, binary.BigEndian, item)
	}
	return buf.Bytes()
}

func MustHexDecode(data string) []byte {
	result, err := hex.DecodeString(data)
	if err != nil {
		return []byte{}
	}
	return result
}

type HashNewFunc func() hash.Hash

func hmacsha1(key, data []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hmacmd5(key, data []byte) []byte {
	mac := hmac.New(md5.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func hashSum(data []byte, h func() hash.Hash) []byte {
	hashInstance := h()
	hashInstance.Write(data)
	return hashInstance.Sum(nil)
}

func hmacSum(key, data []byte, h func() hash.Hash) []byte {
	mac := hmac.New(h, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func matchBegin(str1, str2 []byte) bool {
	if len(str1) >= len(str2) {
		if bytes.Equal(str1[:len(str2)], str2) {
			return true
		}
	}
	return false
}

/* ---------------------------- AuthBase ---------------------------- */
type AuthBase struct {
	Plain
	// UserID 是本会话从 auth 包里解出的账号身份；解不出的代际（auth_sha1_v4）与
	// 多端口模式留空，连接计数改取 ServerInfo.Identity
	UserID             []byte
	Method             string
	NoCompatibleMethod string
	Overhead           int
	RawTrans           bool
}

// SessionKey 返回这条会话该归到哪个连接计数桶：auth 包解得出身份就用它（单端口），
// 解不出来时用建连时下发的账号身份（多端口下即监听端口）。
// 两者都没有时不能退回空键——那会把整机所有端口挤进同一个桶，client_limit 变成全节点共享
func (authBase *AuthBase) SessionKey() []byte {
	if len(authBase.UserID) > 0 {
		return authBase.UserID
	}
	return authBase.GetServerInfo().GetIdentity()
}

func NewAuthBase(method string) (*AuthBase, error) {
	newPlain, err := NewPlain(method)
	if err != nil {
		return nil, err
	}
	return &AuthBase{
		Plain:    newPlain,
		Method:   method,
		Overhead: 4,
	}, nil
}

func (authBase *AuthBase) GetOverhead(direction bool) int {
	return authBase.Overhead
}

func (authBase *AuthBase) NotMatchReturn(buf []byte) ([]byte, bool) {
	authBase.RawTrans = true
	authBase.Overhead = 0
	if authBase.GetMethod() == authBase.NoCompatibleMethod {
		return bytes.Repeat([]byte{byte('E')}, 2048), false
	}
	return buf, false
}

/* ---------------------------- ClientQueue ---------------------------- */

type ClientQueue struct {
	Front      int
	Back       int
	Alloc      *sync.Map
	Enable     bool
	LastUpdate time.Time
	Ref        int
}

func NewClientQueue(beginID int) *ClientQueue {
	return &ClientQueue{
		Front:      beginID - 64,
		Back:       beginID + 1,
		Alloc:      new(sync.Map),
		Enable:     true,
		LastUpdate: time.Now(),
		Ref:        0,
	}
}

func (c *ClientQueue) Update() {
	c.LastUpdate = time.Now()
}

func (c *ClientQueue) AddRef() {
	c.Ref += 1
}

func (c *ClientQueue) DelRef() {
	if c.Ref > 0 {
		c.Ref -= 1
	}
}

func (c *ClientQueue) IsActive() bool {
	return c.Ref > 0 && time.Now().Sub(c.LastUpdate).Seconds() < 60*10
}

func (c *ClientQueue) ReEnable(connectionID int) {
	c.Enable = true
	c.Front = connectionID - 64
	c.Back = connectionID + 1
	c.Alloc = new(sync.Map)
}

func (c *ClientQueue) Insert(connectionID int) bool {
	if !c.Enable {
		log.Warn("obfs auth: not enable")
		return false
	}
	if !c.IsActive() {
		c.ReEnable(connectionID)
	}
	c.Update()
	if connectionID < c.Front {
		log.Warn("obfs auth: deprecated ID, someone replay attack")
		return false
	}
	if connectionID > c.Front+0x4000 {
		log.Warn("obfs auth: wrong ID")
		return false
	}
	if _, ok := c.Alloc.Load(connectionID); ok {
		log.Warn("obfs auth: deprecated ID, someone replay attack")
		return false
	}
	if c.Back <= connectionID {
		c.Back = connectionID + 1
	}
	c.Alloc.Store(connectionID, 1)
	// 回收窗口：只要 front 还分配着、或者窗口超过 0x1000，就把它往前推。
	// 判据看 Front（不是 Back）——Back 是下一个未分配 ID，永远不在 Alloc 里
	for {
		_, frontAllocated := c.Alloc.Load(c.Front)
		if !frontAllocated && c.Front+0x1000 >= c.Back {
			break
		}
		if frontAllocated {
			c.Alloc.Delete(c.Front)
		}
		c.Front += 1
	}
	c.AddRef()
	return true
}

/* ---------------------------- ObfsAuthChainData ---------------------------- */

type ObfsAuthChainData struct {
	Name string
	// mu 罩住 Buckets、MaxClient/MaxBuffer 与 ConnectionID/LocalClientId：
	// 这个单例被全部监听端口的每连接、每包协程共用，漏一处锁就是不可 recover 的进程 fatal
	mu sync.Mutex
	// Buckets 按账号身份（4 字节小端的字符串形式）各挂一个连接 id 计数桶，
	// MaxClient 是每桶上限，不是全节点上限
	Buckets       map[string]*cache.LRU
	LocalClientId []byte
	ConnectionID  uint32
	MaxClient     int
	stop          chan struct{}
	stopOnce      sync.Once
}

func NewObfsAuthChainData(name string) *ObfsAuthChainData {
	result := &ObfsAuthChainData{
		Name:          name,
		Buckets:       make(map[string]*cache.LRU),
		LocalClientId: []byte{},
		ConnectionID:  0,
		stop:          make(chan struct{}),
	}
	result.SetMaxClient(64)
	// 每个账号的桶里各有一个 janitor；桶本身只在空掉之后才会被回收，这里定期扫掉空桶
	go goroutine.Protect(func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				result.gcBuckets()
			case <-result.stop:
				return
			}
		}
	})
	return result
}

// Close 停掉桶回收协程与所有桶的 janitor；节点重载替换单例时调用
func (o *ObfsAuthChainData) Close() {
	o.stopOnce.Do(func() { close(o.stop) })

	o.mu.Lock()
	buckets := o.Buckets
	o.Buckets = make(map[string]*cache.LRU)
	o.mu.Unlock()

	for _, bucket := range buckets {
		bucket.Stop()
	}
}

func (o *ObfsAuthChainData) gcBuckets() {
	o.mu.Lock()
	var empty []*cache.LRU
	for key, bucket := range o.Buckets {
		if bucket.Len() == 0 {
			delete(o.Buckets, key)
			empty = append(empty, bucket)
		}
	}
	o.mu.Unlock()

	for _, bucket := range empty {
		bucket.Stop()
	}
}

func (o *ObfsAuthChainData) Update(userID []byte, clientID, connectionID int) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.Buckets[string(userID)] == nil {
		o.Buckets[string(userID)] = cache.NewLruCache(60 * time.Second)
	}
	localClientID := o.Buckets[string(userID)]
	var r *ClientQueue = nil
	if localClientID != nil {
		r, _ = localClientID.Get(clientID).(*ClientQueue)
	}
	if r != nil {
		r.Update()
	}
}

func (o *ObfsAuthChainData) SetMaxClient(maxClient int) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.MaxClient = maxClient
}

func (o *ObfsAuthChainData) Insert(userID []byte, clientID, connectionID int) bool {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.Buckets[string(userID)] == nil {
		o.Buckets[string(userID)] = cache.NewLruCache(60 * time.Second)
	}
	localClientID := o.Buckets[string(userID)]
	var r, _ = localClientID.Get(clientID).(*ClientQueue)
	if r == nil || !r.Enable {
		if localClientID.First() == nil || localClientID.Len() < o.MaxClient {
			log.Info("new client: %d, user: %d", clientID, binaryx.LEBytesToUInt32(userID))
			if !localClientID.IsExist(clientID) {
				localClientID.Put(clientID, NewClientQueue(connectionID))
			} else {
				localClientID.Get(clientID).(*ClientQueue).ReEnable(connectionID)
			}
			return localClientID.Get(clientID).(*ClientQueue).Insert(connectionID)
		}

		localClientIDFirst := localClientID.First()
		if localClientIDFirst != nil && !localClientID.Get(localClientIDFirst).(*ClientQueue).IsActive() {
			localClientID.Delete(localClientIDFirst)
			if !localClientID.IsExist(clientID) {
				localClientID.Put(clientID, NewClientQueue(connectionID))
			} else {
				localClientID.Get(clientID).(*ClientQueue).ReEnable(connectionID)
			}
			return localClientID.Get(clientID).(*ClientQueue).Insert(connectionID)
		}

		log.Warn("uid: %d, clientId: %d - %s: no inactive client", binaryx.LEBytesToUInt32(userID), clientID, o.Name)
		return false
	} else {
		return localClientID.Get(clientID).(*ClientQueue).Insert(connectionID)
	}
}

func (o *ObfsAuthChainData) Remove(userID string, clientID int) {
	o.mu.Lock()
	defer o.mu.Unlock()

	localClientID := o.Buckets[string(userID)]
	if localClientID != nil {
		if localClientID.IsExist(clientID) {
			localClientID.Get(clientID).(*ClientQueue).DelRef()
		}
	}
}

func (o *ObfsAuthChainData) AuthData() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()

	utcTime := uint32(time.Now().Unix() & 0xFFFFFFFF)
	if o.ConnectionID > 0xFF000000 {
		o.LocalClientId = []byte{}
	}
	if o.LocalClientId == nil || len(o.LocalClientId) == 0 {
		o.LocalClientId = randomx.RandomBytes(4)
		o.ConnectionID = binaryx.LEBytesToUInt32(randomx.RandomBytes(4))
	}
	o.ConnectionID++
	return bytesx.ContactSlice(
		binaryx.LEUint32ToBytes(uint32(utcTime)),
		o.LocalClientId,
		binaryx.LEUint32ToBytes(o.ConnectionID),
	)
}
