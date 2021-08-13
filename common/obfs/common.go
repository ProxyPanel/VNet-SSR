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
	"math"
	"sync"
	"time"

	"github.com/ProxyPanel/VNet-SSR/common/cache"
	"github.com/ProxyPanel/VNet-SSR/common/log"
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
	Method             string
	NoCompatibleMethod string
	Overhead           int
	RawTrans           bool
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
	for {
		if _, ok := c.Alloc.Load(c.Back); !ok || c.Front+0x1000 >= c.Back {
			break
		}
		if _, ok := c.Alloc.Load(c.Front); ok {
			c.Alloc.Delete(c.Front)
		}
		c.Front += 1
	}
	c.AddRef()
	return true
}

/* ---------------------------- ObfsAuthChainData ---------------------------- */

type ObfsAuthChainData struct {
	Name          string
	UserID        map[string]*cache.LRU
	LocalClientId []byte
	ConnectionID  int
	MaxClient     int
	MaxBuffer     int
}

func NewObfsAuthChainData(name string) *ObfsAuthChainData {
	result := &ObfsAuthChainData{
		Name:          name,
		UserID:        make(map[string]*cache.LRU),
		LocalClientId: []byte{},
		ConnectionID:  0,
	}
	result.SetMaxClient(64)
	return result
}

func (o *ObfsAuthChainData) Update(userID []byte, clientID, connectionID int) {
	if o.UserID[string(userID)] == nil {
		o.UserID[string(userID)] = cache.NewLruCache(60 * time.Second)
	}
	localClientID := o.UserID[string(userID)]
	var r *ClientQueue = nil
	if localClientID != nil {
		r, _ = localClientID.Get(clientID).(*ClientQueue)
	}
	if r != nil {
		r.Update()
	}
}

func (o *ObfsAuthChainData) SetMaxClient(maxClient int) {
	o.MaxClient = maxClient
	o.MaxBuffer = int(math.Max(float64(maxClient), 1024))
}

func (o *ObfsAuthChainData) Insert(userID []byte, clientID, connectionID int) bool {
	if o.UserID[string(userID)] == nil {
		o.UserID[string(userID)] = cache.NewLruCache(60 * time.Second)
	}
	localClientID := o.UserID[string(userID)]
	var r, _ = localClientID.Get(clientID).(*ClientQueue)
	if r == nil || !r.Enable {
		if localClientID.First() == nil || localClientID.Len() < o.MaxClient {
			log.Info("new client: %d, user: %d", clientID, binaryx.LEBytesToUInt32(userID))
			if !localClientID.IsExist(clientID) {
				// TODO check
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
				// TODO check
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
	localClientID := o.UserID[string(userID)]
	if localClientID != nil {
		if localClientID.IsExist(clientID) {
			localClientID.Get(clientID).(*ClientQueue).DelRef()
		}
	}
}

func (o *ObfsAuthChainData) AuthData() []byte {
	utcTime := uint32(time.Now().Unix() & 0xFFFFFFFF)
	if o.ConnectionID > 0xFF000000 {
		o.LocalClientId = []byte{}
	}
	if o.LocalClientId == nil || len(o.LocalClientId) == 0 {
		o.LocalClientId = randomx.RandomBytes(4)
		//log.Debug("local_client_id %s", hex.EncodeToString(o.ObfsAuthChainDato.LocalClientId))
		o.ConnectionID = int(binaryx.LEBytesToUInt32(randomx.RandomBytes(4)) & 0xFFFFFFFF)
	}
	o.ConnectionID++
	return bytesx.ContactSlice(
		binaryx.LEUint32ToBytes(uint32(utcTime)),
		o.LocalClientId,
		binaryx.LEUint32ToBytes(uint32(o.ConnectionID)),
	)
}

func (o *ObfsAuthChainData) GetConnectionID() int {
	return o.ConnectionID
}

func (o *ObfsAuthChainData) SetConnectionID(connectionID int) {
	o.ConnectionID = connectionID
}

func (o *ObfsAuthChainData) SetClientID(clientID []byte) {
	o.LocalClientId = clientID
}

func (o *ObfsAuthChainData) GetClientID() []byte {
	return o.LocalClientId
}
