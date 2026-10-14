package obfs

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/core"
	"hash"
	"math"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/ProxyPanel/VNet-SSR/common/ciphers"
	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/utils/arrayx"
	"github.com/ProxyPanel/VNet-SSR/utils/binaryx"
	"github.com/ProxyPanel/VNet-SSR/utils/bytesx"
	"github.com/ProxyPanel/VNet-SSR/utils/randomx"
	"github.com/pkg/errors"
)

func init() {
	registerMethod("auth_aes128_md5", AuthAes128Md5Factory)
	registerMethod("auth_aes128_sha1", AuthAes128Sha1Factory)
	registerIdentityBearing("auth_aes128_md5", "auth_aes128_sha1")
}

func AuthAes128Md5Factory(method string) (Plain, error) {
	if core.GetApp().GetObfsProtocolService() == nil {
		return nil, errors.New("obfs protocol service is nil")
	}
	return NewAuthAes128Sha1(method, md5.New)
}

func AuthAes128Sha1Factory(method string) (Plain, error) {
	if core.GetApp().GetObfsProtocolService() == nil {
		return nil, errors.New("obfs protocol service is nil")
	}
	return NewAuthAes128Sha1(method, sha1.New)
}

type AuthAes128Sha1 struct {
	*AuthBase
	*ObfsAuthChainData
	HashFunc      func() hash.Hash
	RecvBuf       []byte
	UnitLen       int
	RawTrans      bool
	HasRecvHeader bool
	HasSentHeader bool
	ClientID      int
	ConnectionID  uint32
	MaxTimeDif    int
	Salt          []byte
	ExtraWaitSize int
	PackID        uint32
	RecvID        uint32
	UserKey       []byte
	LastRndLen    int
}

func NewAuthAes128Sha1(method string, handle func() hash.Hash) (Plain, error) {
	authAes128Sha1 := new(AuthAes128Sha1)
	newAuthBase, err := NewAuthBase(method)
	if err != nil {
		return nil, err
	}
	authAes128Sha1.AuthBase = newAuthBase
	authAes128Sha1.Method = method
	authAes128Sha1.RecvBuf = []byte{}
	authAes128Sha1.UnitLen = 8100
	authAes128Sha1.RawTrans = false
	authAes128Sha1.HasRecvHeader = false
	authAes128Sha1.HasSentHeader = false
	authAes128Sha1.ClientID = 0
	authAes128Sha1.MaxTimeDif = 60 * 60 * 24
	authAes128Sha1.HashFunc = handle
	if reflect.ValueOf(authAes128Sha1.HashFunc).Pointer() == reflect.ValueOf(md5.New).Pointer() {
		authAes128Sha1.Salt = []byte("auth_aes128_md5")
		authAes128Sha1.NoCompatibleMethod = "auth_aes128_md5"
	}

	if reflect.ValueOf(authAes128Sha1.HashFunc).Pointer() == reflect.ValueOf(sha1.New).Pointer() {
		authAes128Sha1.Salt = []byte("auth_aes128_sha1")
		authAes128Sha1.NoCompatibleMethod = "auth_aes128_sha1"
	}

	authAes128Sha1.ExtraWaitSize = randomx.RandIntRange(0, 1024)
	authAes128Sha1.PackID = 1
	authAes128Sha1.RecvID = 1
	authAes128Sha1.UserID = nil
	authAes128Sha1.UserKey = nil
	authAes128Sha1.LastRndLen = 0
	authAes128Sha1.Overhead = 9
	return authAes128Sha1, nil
}

// SetServerInfo 里 protocol_param 的「#」前段是并发客户端上限（mu 形态下「#」后跟 uid:passwd 用户表，
// 那张表由账号下发通道负责，这里不解析）。取不到整数时保留已设的值，不在每条连接上重置
func (a *AuthAes128Sha1) SetServerInfo(s ServerInfo) {
	a.AuthBase.SetServerInfo(s)
	if v, err := strconv.Atoi(strings.SplitN(s.GetProtocolParam(), "#", 2)[0]); err == nil {
		core.GetApp().GetObfsProtocolService().SetMaxClient(v)
	}
}

func (a *AuthAes128Sha1) trapezoidRandomFloat(d float64) float64 {
	if d == 0 {
		return randomx.Float64()
	}
	s := rand.Float64()
	tmp := 1 - d
	return (math.Sqrt(tmp*tmp+4*d*s) - tmp) / (2 * d)
}

func (a *AuthAes128Sha1) trapezoidRandomInt(maxVal, d float64) int {
	v := a.trapezoidRandomFloat(d)
	return int(v * maxVal)
}

func (a *AuthAes128Sha1) rndDataLen(bufSize, fullBufSize int) int {
	if fullBufSize >= a.GetServerInfo().GetBufferSize() {
		return 0
	}
	tcpMss := a.GetServerInfo().GetTCPMss()
	revLen := tcpMss - bufSize - 9
	if revLen == 0 {
		return 0
	}
	if revLen < 0 {
		if revLen > -tcpMss {
			return a.trapezoidRandomInt(float64(revLen+tcpMss), -0.3)
		}
		return randomx.RandIntRange(0, 32)
	}

	if bufSize > 900 {
		return randomx.RandIntRange(0, revLen)
	}

	return a.trapezoidRandomInt(float64(revLen), -0.3)
}

func (a *AuthAes128Sha1) rndData(bufSize, fullBufSize int) []byte {
	dataLen := a.rndDataLen(bufSize, fullBufSize)
	if dataLen < 128 {
		return bytesx.ContactSlice([]byte{byte(int8(dataLen + 1))}, randomx.RandomBytes(dataLen))
	}
	return bytesx.ContactSlice([]byte{byte(255)}, binaryx.LEUInt16ToBytes(uint16(dataLen+1)), randomx.RandomBytes(dataLen-2))
}

func (a *AuthAes128Sha1) packData(buf []byte, fullBufSize int) []byte {
	data := bytesx.ContactSlice(a.rndData(len(buf), fullBufSize), buf)
	dataLen := len(data) + 8
	macKey := bytesx.ContactSlice(a.UserKey, binaryx.LEUint32ToBytes(a.PackID))
	mac := hmacSum(macKey, binaryx.LEUInt16ToBytes(uint16(dataLen)), a.HashFunc)[:2]
	data = bytesx.ContactSlice(binaryx.LEUInt16ToBytes(uint16(dataLen)), mac, data)
	data = bytesx.ContactSlice(data, hmacSum(macKey, data, a.HashFunc)[:4])
	a.PackID++
	return data
}

func (a *AuthAes128Sha1) packAuthData(authData, buf []byte) ([]byte, error) {
	var rndLen uint16
	if len(buf) == 0 {
		return []byte{}, nil
	}
	if len(buf) > 400 {
		rndLen = binaryx.LEBytesToUint16(randomx.RandomBytes(2)) % 512
	} else {
		rndLen = binaryx.LEBytesToUint16(randomx.RandomBytes(2)) % 1024
	}
	data := authData
	dataLen := 7 + 4 + 16 + 4 + len(buf) + int(rndLen) + 4
	data = bytesx.ContactSlice(data, binaryx.LEUInt16ToBytes(uint16(dataLen)), binaryx.LEUInt16ToBytes(rndLen))
	macKey := bytesx.ContactSlice(a.GetServerInfo().GetIv(), a.GetServerInfo().GetKey())

	param := a.GetServerInfo().GetProtocolParam()
	uidPack := randomx.RandomBytes(4)
	if strings.Contains(param, ":") {
		items := strings.Split(param, ":")
		if len(items) > 1 {
			a.UserKey = hashSum([]byte(items[1]), a.HashFunc)
			uidInt, err := strconv.Atoi(items[0])
			if err != nil {
				return nil, err
			}
			uidPack = binaryx.LEUint32ToBytes(uint32(uidInt))
		} else {
			return nil, errors.New(fmt.Sprintf("obfs param error: %s", param))
		}
	}

	if a.UserKey == nil {
		// protocol_param 不带 uid:passwd 即多端口：身份编号随机、会话 key 用本端口自己的密钥，
		// 与本文件 ClientUDPPreEncrypt 以及 auth_chain 的同名分支同一条判据
		a.UserKey = a.GetServerInfo().GetKey()
	}
	encryptor, err := ciphers.NewEncryptorWithIv("aes-128-cbc",
		string(bytesx.ContactSlice([]byte(base64.StdEncoding.EncodeToString(a.UserKey)), a.Salt)),
		bytes.Repeat([]byte{0x00}, 16))
	if err != nil {
		return nil, err
	}
	dataEncrypt, err := encryptor.Encrypt(data)
	if err != nil {
		return nil, err
	}
	data = bytesx.ContactSlice(uidPack, dataEncrypt[16:])
	data = bytesx.ContactSlice(data, hmacSum(macKey, data, a.HashFunc)[:4])
	checkHead := randomx.RandomBytes(1)
	checkHead = bytesx.ContactSlice(checkHead, hmacSum(macKey, checkHead, a.HashFunc)[:6])
	data = bytesx.ContactSlice(checkHead, data, randomx.RandomBytes(int(rndLen)), buf)
	data = bytesx.ContactSlice(data, hmacSum(a.UserKey, data, a.HashFunc)[:4])
	return data, nil
}

func (a *AuthAes128Sha1) ClientPreEncrypt(buf []byte) (result []byte, err error) {
	result = []byte{}
	originDataLen := len(buf)
	// seem not be used. copy from shadowsocksr python version
	//ognDataLen := len(buf)
	if !a.HasSentHeader {
		headSize := a.GetHeadSize(buf, 30)
		dataLen := int(math.Min(float64(len(buf)), float64(randomx.RandIntRange(0, 31)+headSize)))
		packAuthData, err := a.packAuthData(core.GetApp().GetObfsProtocolService().AuthData(), buf[:dataLen])
		if err != nil {
			return nil, err
		}
		result = bytesx.ContactSlice(result, packAuthData)
		buf = buf[dataLen:]
		a.HasSentHeader = true
	}
	for len(buf) > a.UnitLen {
		result = bytesx.ContactSlice(result, a.packData(buf[:a.UnitLen], originDataLen))
		buf = buf[a.UnitLen:]
	}
	result = bytesx.ContactSlice(result, a.packData(buf, originDataLen))
	a.LastRndLen = originDataLen
	return result, nil
}

func (a *AuthAes128Sha1) ClientPostDecrypt(buf []byte) (result []byte, err error) {
	if a.RawTrans {
		return buf, nil
	}
	a.RecvBuf = bytesx.ContactSlice(a.RecvBuf, buf)
	result = []byte{}
	for len(a.RecvBuf) > 4 {
		macKey := bytesx.ContactSlice(a.UserKey, binaryx.LEUint32ToBytes(a.RecvID))
		mac := hmacSum(macKey, a.RecvBuf[:2], a.HashFunc)[:2]
		if !bytes.Equal(mac, a.RecvBuf[2:4]) {
			return nil, errors.New("client_post_decrypt data uncorrect mac")
		}
		length := binaryx.LEBytesToUint16(a.RecvBuf[:2])
		if length >= 8129 || length < 7 {
			a.RawTrans = true
			a.RecvBuf = []byte{}
			return nil, errors.New("client_post_decrypt data error")
		}
		if int(length) > len(a.RecvBuf) {
			break
		}
		if !bytes.Equal(hmacSum(macKey, a.RecvBuf[:length-4], a.HashFunc)[:4], a.RecvBuf[length-4:length]) {
			a.RawTrans = true
			a.RecvBuf = []byte{}
			return nil, errors.New("client_post_decrypt data uncorrect checksum")
		}

		a.RecvID++
		pos := int(a.RecvBuf[4])
		if pos < 255 {
			pos += 4
		} else {
			pos = int(binaryx.LEBytesToUint16(a.RecvBuf[5:7]) + 4)
		}
		result = bytesx.ContactSlice(result, a.RecvBuf[pos:length-4])
		a.RecvBuf = a.RecvBuf[length:]
	}
	return result, nil
}

func (a *AuthAes128Sha1) ServerPreEncrypt(buf []byte) ([]byte, error) {
	if a.RawTrans {
		return buf, nil
	}

	result := []byte{}
	originDataLength := len(buf)
	for len(buf) > a.UnitLen {
		result = bytesx.ContactSlice(result, a.packData(buf[:a.UnitLen], originDataLength))
		buf = buf[a.UnitLen:]
	}
	result = bytesx.ContactSlice(result, a.packData(buf, originDataLength))
	a.LastRndLen = originDataLength
	return result, nil
}

func (a *AuthAes128Sha1) ServerPostDecrypt(buf []byte) (result []byte, sendback bool, err error) {
	if a.RawTrans {
		return buf, false, nil
	}
	a.RecvBuf = bytesx.ContactSlice(a.RecvBuf, buf)
	result = []byte{}
	sendback = false

	if !a.HasRecvHeader {
		var macKey []byte
		var sha1Data []byte
		if len(a.RecvBuf) >= 7 || arrayx.In(len(a.RecvBuf), []int{2, 3}) {
			recvLen := int(math.Min(float64(len(a.RecvBuf)), float64(7)))
			macKey = bytesx.ContactSlice(a.GetServerInfo().GetRecvIv(), a.GetServerInfo().GetKey())
			sha1Data = hmacSum(macKey, a.RecvBuf[:1], a.HashFunc)[:recvLen-1]
			if !bytes.Equal(sha1Data, a.RecvBuf[1:recvLen]) {
				result, sendback = a.NotMatchReturn(a.RecvBuf)
				return
			}
		}

		if len(a.RecvBuf) < 31 {
			return []byte{}, false, nil
		}

		sha1Data = hmacSum(macKey, a.RecvBuf[7:27], a.HashFunc)[:4]
		if !bytes.Equal(sha1Data, a.RecvBuf[27:31]) {
			log.Error("%s data uncorrect auth HMAC-SHA1 from %s:%d ,data %s",
				a.NoCompatibleMethod, a.GetServerInfo().GetClient(), a.GetServerInfo().GetClientPort(),
				hex.EncodeToString(a.RecvBuf))
			if len(a.RecvBuf) < 31+a.ExtraWaitSize {
				return []byte{}, false, nil
			}
			result, sendback = a.NotMatchReturn(a.RecvBuf)
			return
		}

		// 报文里这 4 字节按 SSR 线格式叫 uid，本后端约定它装的是账号的端口号
		// （契约见 docs/openapi.yaml 的 UserInfo.port）：密码表 GetUsers() 的键由 proxy/server 的
		// AddUser(identity) 打包，UpdateUser 也把它写回会话身份。
		// 空密码不算账号：写入侧就拒绝空密码（等于开放账号），表里出现它只能是手改配置，按不认识处理
		uidPack := a.RecvBuf[7:11]
		if passwd := a.GetServerInfo().GetUsers()[string(uidPack)]; passwd != "" {
			a.UserID = uidPack
			a.UserKey = hashSum([]byte(passwd), a.HashFunc)
			a.GetServerInfo().UpdateUser(uidPack)
		} else if len(a.GetServerInfo().GetUsers()) == 0 {
			// 多端口：每个监听端口自己就是一个账号，密码表恒空，两端都按本端口密钥算会话 key，
			// 包里的身份编号随包随机、不参与记账
			a.UserKey = a.GetServerInfo().GetKey()
		} else {
			// 单端口且不认识这个身份（账号已摘、客户端还拿旧订阅重连）：表上没有这个账号，
			// 就没有任何 key 能验证这条流，按握手不匹配收尾即可。继续往下只会在必然失配之后再
			// 落回同一出口，中间还多等一轮读包、把连接挂在半开状态
			result, sendback = a.NotMatchReturn(a.RecvBuf)
			return
		}

		encryptor, err := ciphers.NewEncryptorWithIv("aes-128-cbc",
			string(bytesx.ContactSlice([]byte(base64.StdEncoding.EncodeToString(a.UserKey)), a.Salt)),
			bytes.Repeat([]byte{0x00}, 16))

		if err != nil {
			return []byte{}, false, err
		}
		head, err := encryptor.Decrypt(bytesx.ContactSlice(bytes.Repeat([]byte{0x00}, 16), a.RecvBuf[11:27]))
		if err != nil {
			return []byte{}, false, err
		}
		length := binaryx.LEBytesToUint16(head[12:14])
		if len(a.RecvBuf) < int(length) {
			return []byte{}, false, nil
		}
		// length 取自解密结果，包头损坏时它是垃圾：负下标切片会 panic，先按握手不匹配收尾
		if length < 7 {
			result, sendback = a.NotMatchReturn(a.RecvBuf)
			return result, sendback, nil
		}
		utcTime := binaryx.LEBytesToUInt32(head[:4])
		clientId := binaryx.LEBytesToUInt32(head[4:8])
		connectionId := binaryx.LEBytesToUInt32(head[8:12])
		rndLen := binaryx.LEBytesToUint16(head[14:16])
		macData := hmacSum(a.UserKey, a.RecvBuf[:length-4], a.HashFunc)[:4]
		if !bytes.Equal(macData, a.RecvBuf[length-4:length]) {
			log.Error("%s: checksum error, data %s", a.NoCompatibleMethod, hex.EncodeToString(a.RecvBuf[:length]))
			result, sendback = a.NotMatchReturn(a.RecvBuf)
			return result, sendback, nil
		}
		timeDif := int(int64(utcTime) - time.Now().Unix()&0xFFFFFFFF)
		if timeDif < -a.MaxTimeDif || timeDif > a.MaxTimeDif {
			log.Info("%s: wrong timestamp, time_dif %v, data %s",
				a.NoCompatibleMethod,
				timeDif,
				hex.EncodeToString(head))
			result, sendback = a.NotMatchReturn(a.RecvBuf)
			return result, sendback, nil
		} else if core.GetApp().GetObfsProtocolService().Insert(a.SessionKey(), int(clientId), int(connectionId)) {
			a.HasRecvHeader = true
			result = a.RecvBuf[31+rndLen : length-4]
			a.ClientID = int(clientId)
			a.ConnectionID = connectionId
		} else {
			log.Info("%s: auth fail, data %s", a.NoCompatibleMethod, hex.EncodeToString(result))
			result, sendback = a.NotMatchReturn(a.RecvBuf)
			return result, sendback, nil
		}
		a.RecvBuf = a.RecvBuf[length:]
		a.HasRecvHeader = true
		sendback = true
	}
	for len(a.RecvBuf) > 4 {
		macKey := bytesx.ContactSlice(a.UserKey, binaryx.LEUint32ToBytes(a.RecvID))
		mac := hmacSum(macKey, a.RecvBuf[:2], a.HashFunc)[:2]
		if !bytes.Equal(mac, a.RecvBuf[2:4]) {
			a.RawTrans = true
			log.Info("%s %s", a.NoCompatibleMethod, ": wrong crc")
			if a.RecvID == 0 {
				return bytes.Repeat([]byte{byte('E')}, 2048), false, nil
			}
			return []byte{}, false, errors.New("server_post_decrype data error")
		}

		length := int(binaryx.LEBytesToUint16(a.RecvBuf[:2]))
		if length >= 8192 || length < 7 {
			a.RawTrans = true
			a.RecvBuf = []byte{}
			if a.RecvID == 0 {
				log.Error("%s %s", a.NoCompatibleMethod, "over size")
				return bytes.Repeat([]byte{byte('E')}, 2048), false, nil
			} else {
				return []byte{}, false, errors.New("server_post_decrype data error")
			}
		}

		if length > len(a.RecvBuf) {
			break
		}

		macData := hmacSum(macKey, a.RecvBuf[:length-4], a.HashFunc)[:4]
		if !bytes.Equal(macData, a.RecvBuf[length-4:length]) {
			log.Error("%s: checksum error, data %s", a.NoCompatibleMethod, hex.EncodeToString(a.RecvBuf[:length]))
			a.RawTrans = true
			a.RecvBuf = []byte{}
			if a.RecvID == 0 {
				return bytes.Repeat([]byte{byte('E')}, 2048), false, nil
			}
			return []byte{}, false, errors.New("server_post_decrype data uncorrect checksum")
		}

		a.RecvID++
		pos := int(a.RecvBuf[4])
		if pos < 255 {
			pos += 4
		} else {
			pos = int(binaryx.LEBytesToUint16(a.RecvBuf[5:7]) + 4)
		}
		result = bytesx.ContactSlice(result, a.RecvBuf[pos:length-4])
		a.RecvBuf = a.RecvBuf[length:]
		if pos == length-4 {
			sendback = true
		}
	}
	if len(result) > 0 {
		core.GetApp().GetObfsProtocolService().Update(a.SessionKey(), a.ClientID, int(a.ConnectionID))
	}
	return result, sendback, nil
}

func (a *AuthAes128Sha1) ClientUDPPreEncrypt(buf []byte) ([]byte, error) {
	if a.UserKey == nil {
		param := a.GetServerInfo().GetProtocolParam()
		if strings.Contains(param, ":") {
			items := strings.Split(param, ":")
			if len(items) > 1 {
				a.UserKey = hashSum([]byte(items[1]), a.HashFunc)
				uidInt, err := strconv.Atoi(items[0])
				if err != nil {
					return nil, err
				}
				uidPack := binaryx.LEUint32ToBytes(uint32((uidInt)))
				a.UserID = uidPack
			}

		}
		if a.UserKey == nil {
			a.UserID = randomx.RandomBytes(4)
			a.UserKey = a.GetServerInfo().GetKey()
		}
	}
	buf = bytesx.ContactSlice(buf, a.UserID)
	return bytesx.ContactSlice(buf, hmacSum(a.UserKey, buf, a.HashFunc)[:4]), nil
}

func (a *AuthAes128Sha1) ClientUDPPostDecrypt(buf []byte) ([]byte, error) {
	userKey := a.GetServerInfo().GetKey()
	macData := hmacSum(userKey, buf[0:len(buf)-4], a.HashFunc)[:4]
	if !bytes.Equal(macData, buf[len(buf)-4:]) {
		return []byte{}, nil
	}
	return buf[0 : len(buf)-4], nil
}

func (a *AuthAes128Sha1) ServerUDPPreEncrypt(buf, uid []byte) ([]byte, error) {
	userKey := a.GetServerInfo().GetKey()
	return bytesx.ContactSlice(buf, hmacSum(userKey, buf, a.HashFunc)[:4]), nil
}

func (a *AuthAes128Sha1) ServerUDPPostDecrypt(buf []byte) ([]byte, string, error) {
	var userKey []byte
	uidPack := buf[len(buf)-8 : len(buf)-4]
	if passwd := a.GetServerInfo().GetUsers()[string(uidPack)]; passwd != "" {
		userKey = hashSum([]byte(passwd), a.HashFunc)
	} else {
		// 认不出这个身份就不能把它当账号带出去：调用方按返回的 uid 记账与回包
		uidPack = nil
		if len(a.GetServerInfo().GetUsers()) == 0 {
			// 多端口：本端口自己就是账号，两端都按本端口密钥封包
			userKey = a.GetServerInfo().GetKey()
		} else {
			// 表上没有这个账号，就没有任何 key 能验证这个包，整包丢弃
			return []byte{}, "", nil
		}
	}
	macData := hmacSum(userKey, buf[:len(buf)-4], a.HashFunc)[:4]
	if !bytes.Equal(macData, buf[len(buf)-4:]) {
		return []byte{}, "", nil
	}
	return buf[:len(buf)-8], string(uidPack), nil
}
