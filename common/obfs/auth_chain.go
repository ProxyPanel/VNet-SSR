package obfs

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/utils/langx"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ProxyPanel/VNet-SSR/common/ciphers"
	"github.com/ProxyPanel/VNet-SSR/utils/bytesx"
	"github.com/ProxyPanel/VNet-SSR/utils/randomx"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/utils/binaryx"
)

const (
	MAX_INT  = (1 << 64) - 1
	MOV_MASK = (1 << (64 - 23)) - 1
)

func init() {
	registerMethod("auth_chain_a", NewAuthChainA)
	registerMethod("auth_chain_b", NewAuthChainB)
	registerMethod("auth_chain_c", NewAuthChainC)
	registerMethod("auth_chain_d", NewAuthChainD)
	registerMethod("auth_chain_e", NewAuthChainE)
	registerMethod("auth_chain_f", NewAuthChainF)
	registerIdentityBearing("auth_chain_a", "auth_chain_b", "auth_chain_c", "auth_chain_d", "auth_chain_e", "auth_chain_f")
}

const (
	chainModeA = iota
	chainModeB
	chainModeC
	chainModeD
	chainModeE
	chainModeF
)

type XorShift128Plus struct {
	V0 uint64
	V1 uint64
}

func NewXorShift128Plus() *XorShift128Plus {
	return &XorShift128Plus{
		V0: 0,
		V1: 0,
	}
}

func (xs1p *XorShift128Plus) Next() uint64 {
	x := xs1p.V0
	y := xs1p.V1
	xs1p.V0 = y
	x ^= ((x & MOV_MASK) << 23)
	x ^= (y ^ (x >> 17) ^ (y >> 26))
	xs1p.V1 = x
	return (x + y) & MAX_INT
}

func (xs1p *XorShift128Plus) InitFromBin(bin []byte) {
	if len(bin) < 16 {
		bin = conbineToBytes(bin, bytes.Repeat([]byte{byte(0x00)}, 16))
	}
	xs1p.V0 = binaryx.LEBytesToUint64(bin[0:8])
	xs1p.V1 = binaryx.LEBytesToUint64(bin[8:16])
}

func (xs1p *XorShift128Plus) InitFromBinLen(bin []byte, length int) {
	if len(bin) < 16 {
		bin = conbineToBytes(bin, bytes.Repeat([]byte{byte(0x00)}, 16))
	}
	xs1p.V0 = binaryx.LEBytesToUint64(conbineToBytes(binaryx.LEUInt16ToBytes(uint16(length)), bin[2:8]))
	xs1p.V1 = binaryx.LEBytesToUint64(bin[8:16])
	for i := 0; i < 4; i++ {
		xs1p.Next()
	}
}

/*----------------------------------AuthChainA----------------------------------*/
type AuthChainA struct {
	*AuthBase
	RecvBuf        []byte
	UnintLen       int
	HasSentHeader  bool
	HasRecvHeader  bool
	ClientID       int
	ConnectionID   uint32
	MaxTimeDif     int
	Salt           []byte
	PackID         uint32
	RecvID         uint32
	UserIDNum      int
	UserKey        []byte
	ClientOverhead int
	LastClientHash []byte
	LastServerHash []byte
	RandomClient   *XorShift128Plus
	RandomServer   *XorShift128Plus
	Encryptor      *ciphers.Encryptor
	// b~f 的补全长度表：同一连接内固定，由服务端 key 派生，两端算出的表必须逐字节一致
	Mode             int
	DataSizeList     []int
	DataSizeList2    []int
	DataSizeList0    []int
	KeyChangeInterva int64
	// 只有服务端在收到 auth 头后推进；0 = 未轮换（客户端恒为此值）
	keyChangeDatetimeKey int64
}

func NewAuthChainA(method string) (Plain, error) {
	return newAuthChain(method, chainModeA)
}

func NewAuthChainB(method string) (Plain, error) {
	return newAuthChain(method, chainModeB)
}

func NewAuthChainC(method string) (Plain, error) {
	return newAuthChain(method, chainModeC)
}

func NewAuthChainD(method string) (Plain, error) {
	return newAuthChain(method, chainModeD)
}

func NewAuthChainE(method string) (Plain, error) {
	return newAuthChain(method, chainModeE)
}

func NewAuthChainF(method string) (Plain, error) {
	return newAuthChain(method, chainModeF)
}

func newAuthChain(method string, mode int) (Plain, error) {
	authBase, err := NewAuthBase(method)
	if err != nil {
		return nil, err
	}
	authBase.RawTrans = false
	authBase.Overhead = 4
	authBase.NoCompatibleMethod = method
	return &AuthChainA{
		AuthBase:       authBase,
		RecvBuf:        []byte{},
		UnintLen:       2800,
		HasRecvHeader:  false,
		HasSentHeader:  false,
		ClientID:       0,
		ConnectionID:   0,
		MaxTimeDif:     60 * 60 * 24,
		Salt:           []byte(method),
		PackID:         1,
		RecvID:         1,
		UserIDNum:      0,
		ClientOverhead: 4,
		LastClientHash: []byte{},
		LastServerHash: []byte{},
		RandomClient:   NewXorShift128Plus(),
		RandomServer:   NewXorShift128Plus(),
		Mode:           mode,
	}, nil
}

// SetServerInfo 里 protocol_param 形如 max_client[#轮换秒数]：前段是并发客户端上限，六代都吃；
// 取不到整数时保留已设的值，不在每条连接上重置。后段只有 f 代用（包长表的时间桶秒数）
func (a *AuthChainA) SetServerInfo(s ServerInfo) {
	a.AuthBase.SetServerInfo(s)
	items := strings.SplitN(s.GetProtocolParam(), "#", 2)
	if v, err := strconv.Atoi(items[0]); err == nil {
		core.GetApp().GetObfsProtocolService().SetMaxClient(v)
	}
	if a.Mode == chainModeA {
		return
	}
	interval := int64(60 * 60 * 24)
	if a.Mode == chainModeF && len(items) > 1 {
		if v, err := strconv.ParseInt(items[1], 10, 64); err == nil && v > 0 {
			interval = v
		}
	}
	a.KeyChangeInterva = interval
	if a.Mode == chainModeF {
		// 建连时两端各自按「当前时间桶」建表；服务端收到 auth 头后再按包头里的 utc_time 重算，
		// 时钟漂移跨过桶界的连接按上游语义自然失配
		a.keyChangeDatetimeKey = time.Now().Unix() / interval
	}
	a.initDataSize(s.GetKey())
}

// initDataSize 用服务端 key 生成补全表；f 模式按时间桶轮换 key（见 onRecvAuthData）
func (a *AuthChainA) initDataSize(key []byte) {
	random := NewXorShift128Plus()
	if a.Mode == chainModeF {
		random.InitFromBin(a.rotatedKey(key))
	} else {
		random.InitFromBin(key)
	}
	next := func() int { return int(random.Next() % 2340 % 2040 % 1440) }

	if a.Mode == chainModeB {
		a.DataSizeList = a.DataSizeList[:0]
		a.DataSizeList2 = a.DataSizeList2[:0]
		for i := 0; i < int(random.Next()%8+4); i++ {
			a.DataSizeList = append(a.DataSizeList, next())
		}
		sort.Ints(a.DataSizeList)
		for i := 0; i < int(random.Next()%16+8); i++ {
			a.DataSizeList2 = append(a.DataSizeList2, next())
		}
		sort.Ints(a.DataSizeList2)
		return
	}

	a.DataSizeList0 = a.DataSizeList0[:0]
	for i := 0; i < int(random.Next()%(8+16)+(4+8)); i++ {
		a.DataSizeList0 = append(a.DataSizeList0, next())
	}
	sort.Ints(a.DataSizeList0)
	if a.Mode == chainModeD || a.Mode == chainModeE || a.Mode == chainModeF {
		oldLen := len(a.DataSizeList0)
		a.checkAndPatchDataSize(random)
		if oldLen != len(a.DataSizeList0) {
			sort.Ints(a.DataSizeList0)
		}
	}
}

func (a *AuthChainA) checkAndPatchDataSize(random *XorShift128Plus) {
	if a.DataSizeList0[len(a.DataSizeList0)-1] < 1300 && len(a.DataSizeList0) < 64 {
		a.DataSizeList0 = append(a.DataSizeList0, int(random.Next()%2340%2040%1440))
		a.checkAndPatchDataSize(random)
	}
}

// rotatedKey：recv_iv ^ md5(recv_iv)[0:4] 按大端铺开成 8 字节再异或进 key 前 8 字节。
// 桶号由建连时间与 auth 包头时间共同决定，两端算进同一桶才会有同一张表
func (a *AuthChainA) rotatedKey(key []byte) []byte {
	if a.keyChangeDatetimeKey == 0 {
		return key
	}
	iv := a.GetServerInfo().GetRecvIv()
	datetimeKey := binaryx.LEBytesToUInt32(iv) ^ binaryx.LEBytesToUInt32(hmacmd5(iv, iv)[:4])
	out := append([]byte{}, key...)
	for i := 0; i < 8 && i < len(out); i++ {
		out[i] ^= byte(datetimeKey >> (8 * (7 - i)))
	}
	return out
}

// onRecvAuthData 只重算服务端一侧的包长表；桶的判据是包头 utc_time，两端各自算出同一个值
func (a *AuthChainA) onRecvAuthData(utcTime uint32) {
	if a.Mode != chainModeF {
		return
	}
	interval := a.KeyChangeInterva
	if interval <= 0 {
		interval = 60 * 60 * 24
	}
	a.keyChangeDatetimeKey = int64(utcTime) / interval
	a.initDataSize(a.GetServerInfo().GetKey())
}

func bisectLeft(list []int, v int) int {
	return sort.SearchInts(list, v)
}

func (a *AuthChainA) GetOverhead(direction bool) int {
	return a.Overhead
}

func (a *AuthChainA) ClientPreEncrypt(buf []byte) (result []byte, err error) {
	result = []byte{}
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
	for len(buf) > a.UnintLen {
		packClientData, err := a.packClientData(buf[:a.UnintLen])
		if err != nil {
			return nil, err
		}
		result = bytesx.ContactSlice(result, packClientData)
		buf = buf[a.UnintLen:]
	}
	packClientData, err := a.packClientData(buf)
	if err != nil {
		return nil, err
	}
	result = bytesx.ContactSlice(result, packClientData)
	return result, nil
}

func (a *AuthChainA) ClientPostDecrypt(buf []byte) (result []byte, err error) {
	if a.RawTrans {
		return buf, nil
	}
	a.RecvBuf = bytesx.ContactSlice(a.RecvBuf, buf)
	result = []byte{}
	for len(a.RecvBuf) > 4 {
		macKey := bytesx.ContactSlice(a.UserKey, binaryx.LEUint32ToBytes(a.RecvID))
		dataLen := int(binaryx.LEBytesToUint16(a.RecvBuf[:2]) ^ binaryx.LEBytesToUint16(a.LastServerHash[14:16]))
		randLen := a.rndDataLen(dataLen, a.LastServerHash, a.RandomServer)
		length := dataLen + randLen
		if length > 4096 {
			a.RawTrans = true
			a.RecvBuf = []byte{}
			return nil, errors.WithStack(errors.New("client_post_decrypt data error"))
		}

		if length+4 > len(a.RecvBuf) {
			break
		}

		serverHash := hmacmd5(macKey, a.RecvBuf[:length+2])
		if !bytes.Equal(serverHash[:2], a.RecvBuf[length+2:length+4]) {
			log.Info("%s checksum error, data: %s", a.NoCompatibleMethod, hex.EncodeToString(a.RecvBuf[:length]))
			a.RawTrans = true
			a.RecvBuf = []byte{}
			return nil, errors.WithStack(errors.New("client_post_decrypt data uncorrect checksum"))
		}

		pos := 2
		if dataLen > 0 && randLen > 0 {
			pos = 2 + a.rndStartPos(randLen, a.RandomServer)
		}
		cleartext, err := a.Encryptor.Decrypt(a.RecvBuf[pos : dataLen+pos])
		if err != nil {
			return nil, err
		}
		result = bytesx.ContactSlice(result, cleartext)
		a.LastServerHash = serverHash
		if a.RecvID == 1 {
			a.GetServerInfo().SetTCPMss(int(binaryx.LEBytesToUint16(result[:2])))
			result = result[2:]
		}
		a.RecvID++
		a.RecvBuf = a.RecvBuf[length+4:]
	}
	return result, nil
}

func (a *AuthChainA) ServerPreEncrypt(buf []byte) (result []byte, err error) {
	if a.RawTrans {
		return buf, nil
	}
	result = []byte{}
	if a.PackID == 1 {
		var tcpMass int
		if a.GetServerInfo().GetTCPMss() < 1500 {
			tcpMass = a.GetServerInfo().GetTCPMss()
		} else {
			tcpMass = 1500
		}
		a.GetServerInfo().SetTCPMss(tcpMass)
		buf = bytesx.ContactSlice(binaryx.LEUInt16ToBytes(uint16(tcpMass)), buf)
		a.UnintLen = tcpMass - a.ClientOverhead
	}

	for len(buf) > a.UnintLen {
		packServerData, err := a.packServerData(buf[:a.UnintLen])
		if err != nil {
			return nil, err
		}
		result = bytesx.ContactSlice(result, packServerData)
		buf = buf[a.UnintLen:]
	}
	packServerData, err := a.packServerData(buf)
	if err != nil {
		return nil, err
	}
	result = bytesx.ContactSlice(result, packServerData)
	return result, nil
}

func (a *AuthChainA) ServerPostDecrypt(buf []byte) (result []byte, sendback bool, err error) {
	if a.RawTrans {
		return buf, false, nil
	}
	a.RecvBuf = bytesx.ContactSlice(a.RecvBuf, buf)
	result = []byte{}
	sendback = false

	var md5Data []byte
	if !a.HasRecvHeader {
		if len(a.RecvBuf) >= 12 || langx.IntIn(len(a.RecvBuf), []int{7, 8}) {
			recvLen := int(math.Min(float64(len(a.RecvBuf)), float64(12)))
			macKey := bytesx.ContactSlice(a.GetServerInfo().GetRecvIv(), a.GetServerInfo().GetKey())
			md5Data = hmacmd5(macKey, a.RecvBuf[:4])
			//logrus.WithFields(
			//	logrus.Fields{
			//		"md5Data":   hex.EncodeToString(md5Data),
			//		"key":       hex.EncodeToString(a.GetServerInfo().GetKey()),
			//		"randBytes": hex.EncodeToString(a.RecvBuf[:4]),
			//		"recvIV":    hex.EncodeToString(a.GetServerInfo().GetRecvIv()),
			//		"recvLen":   recvLen,
			//	}).Debug("AuthChainA verify")
			if !bytes.Equal(md5Data[:recvLen-4], a.RecvBuf[4:recvLen]) {
				logrus.WithFields(logrus.Fields{
					"md5Data":     hex.EncodeToString(md5Data[:recvLen-4]),
					"recvMd5Data": hex.EncodeToString(a.RecvBuf[4:recvLen]),
				}).Error("AuthChainA verify failed")
				result, sendback = a.NotMatchReturn(a.RecvBuf)
				err = nil
				return
			}
		}

		if len(a.RecvBuf) < 12+24 {
			return []byte{}, false, nil
		}

		a.LastClientHash = md5Data

		// 与 auth_aes128 同一约定：解出的这 4 字节线格式叫 uid，本后端约定它装的是账号的端口号，
		// 所以拿它去查以身份编号打包为键的密码表，再经 UpdateUser 写回会话身份。
		// 空密码不算账号：写入侧就拒绝空密码（等于开放账号），表里出现它只能是手改配置
		uid := int(binaryx.LEBytesToUInt32(a.RecvBuf[12:16]) ^ binaryx.LEBytesToUInt32(md5Data[8:12]))
		uidPack := binaryx.LEUint32ToBytes(uint32(uid))
		a.UserIDNum = uid
		if passwd := a.GetServerInfo().GetUsers()[string(uidPack)]; passwd != "" {
			a.UserID = uidPack
			a.UserKey = []byte(passwd)
			a.GetServerInfo().UpdateUser(uidPack)
		} else {
			// 认不出这个身份就不拿它当账号编号，这条连接的流量退回按监听端口记账
			a.UserIDNum = 0
			if len(a.GetServerInfo().GetUsers()) == 0 {
				// 多端口：每个监听端口自己就是一个账号，密码表恒空，
				// 两端都按本端口密钥算会话 key，包里的身份编号随包随机
				a.UserKey = a.GetServerInfo().GetKey()
			} else {
				// 单端口且不认识：表上没有这个账号，就没有任何 key 能验证这条流，
				// 按握手不匹配收尾，不必再解一轮必然失配的包头
				result, sendback = a.NotMatchReturn(a.RecvBuf)
				return
			}
		}

		md5Data = hmacmd5(a.UserKey, a.RecvBuf[12:12+20])
		if !bytes.Equal(md5Data[:4], a.RecvBuf[32:36]) {
			//logrus.WithFields(logrus.Fields{
			//	"md5Data_4": hex.EncodeToString(md5Data[:4]),
			//	"recvBuf_4": hex.EncodeToString(a.RecvBuf[32:36]),
			//}).Debug("auth_chain md5 equal error")
			logrus.Errorf("%s data uncorrect auth HMAC-MD5 from %s:%v, data %s",
				a.NoCompatibleMethod, a.GetServerInfo().
					GetClient().String(),
				a.GetServerInfo().GetPort(),
				hex.EncodeToString(a.RecvBuf))
			if len(a.RecvBuf) < 36 {
				return []byte{}, false, nil
			}
			result, sendback = a.NotMatchReturn(a.RecvBuf)
			return
		}
		a.LastServerHash = md5Data
		encryptor, err := ciphers.NewEncryptorWithIv("aes-128-cbc",
			string(bytesx.ContactSlice([]byte(base64.StdEncoding.EncodeToString(a.UserKey)), a.Salt)),
			bytes.Repeat([]byte{0x00}, 16))
		if err != nil {
			return nil, false, err
		}
		head, err := encryptor.Decrypt(bytesx.ContactSlice(bytes.Repeat([]byte{0x00}, 16), a.RecvBuf[16:32]))
		if err != nil {
			return nil, false, err
		}
		a.ClientOverhead = int(binaryx.LEBytesToUint16(head[12:16]))

		utcTime := binaryx.LEBytesToUInt32(head[:4])
		clientId := binaryx.LEBytesToUInt32(head[4:8])
		connectionId := binaryx.LEBytesToUInt32(head[8:12])
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
			a.ClientID = int(clientId)
			a.ConnectionID = connectionId
			a.onRecvAuthData(utcTime)
		} else {
			log.Info("%s: auth fail, data %s", a.NoCompatibleMethod, hex.EncodeToString(result))
			result, sendback = a.NotMatchReturn(a.RecvBuf)
			return result, sendback, nil
		}
		a.Encryptor, err = ciphers.NewEncryptor(
			"rc4",
			string(
				bytesx.ContactSlice(
					[]byte(base64.StdEncoding.EncodeToString(a.UserKey)),
					[]byte(base64.StdEncoding.EncodeToString(a.LastClientHash)),
				),
			),
		)
		a.RecvBuf = a.RecvBuf[36:]
		a.HasRecvHeader = true
		sendback = true
	}

	for len(a.RecvBuf) > 4 {
		macKey := bytesx.ContactSlice(a.UserKey, binaryx.LEUint32ToBytes(a.RecvID))
		dataLen := binaryx.LEBytesToUint16(a.RecvBuf[:2]) ^ binaryx.LEBytesToUint16(a.LastClientHash[14:16])
		randLen := a.rndDataLen(int(dataLen), a.LastClientHash, a.RandomClient)
		length := int(dataLen) + randLen
		if length >= 4096 {
			a.RawTrans = true
			a.RecvBuf = []byte{}
			if a.RecvID == 1 {
				log.Info("%s: over size ", a.NoCompatibleMethod)
				return bytes.Repeat([]byte{byte('E')}, 2048), false, nil
			} else {
				return nil, false, errors.WithStack(errors.New("server_post_decrype data error"))
			}
		}
		if length+4 > len(a.RecvBuf) {
			break
		}

		clientHash := hmacmd5(macKey, a.RecvBuf[:length+2])
		if !bytes.Equal(clientHash[:2], a.RecvBuf[length+2:length+4]) {
			log.Info("%s checksum error, data %s", a.NoCompatibleMethod, hex.EncodeToString(a.RecvBuf[:length]))
			a.RawTrans = true
			a.RecvBuf = []byte{}
			if a.RecvID == 1 {
				return bytes.Repeat([]byte{byte('E')}, 2048), false, nil
			} else {
				return nil, false, errors.WithStack(errors.New("server_post_decrype data uncorrect checksum"))
			}
		}
		a.RecvID++
		pos := 2
		if dataLen > 0 && randLen > 0 {
			pos = 2 + a.rndStartPos(randLen, a.RandomClient)
		}
		clearText, err := a.Encryptor.Decrypt(a.RecvBuf[pos : int(dataLen)+pos])
		if err != nil {
			return nil, false, err
		}
		result = bytesx.ContactSlice(result, clearText)
		a.LastClientHash = clientHash
		a.RecvBuf = a.RecvBuf[length+4:]
		if dataLen == 0 {
			sendback = true
		}
	}

	if len(result) > 0 {
		core.GetApp().GetObfsProtocolService().Update(a.SessionKey(), a.ClientID, int(a.ConnectionID))
	}
	return result, sendback, nil
}

func (a *AuthChainA) ClientUDPPreEncrypt(buf []byte) ([]byte, error) {
	if a.UserKey == nil {
		param := a.GetServerInfo().GetProtocolParam()
		if strings.Contains(param, ":") {
			items := strings.Split(param, ":")
			if len(items) > 1 {
				md5Data := []byte(items[1])
				a.UserKey = md5Data[:]
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
	authData := randomx.RandomBytes(3)
	macKey := a.GetServerInfo().GetKey()
	md5Data := hmacmd5(macKey, authData)
	uid := binaryx.LEBytesToUInt32(a.UserID) ^ binaryx.LEBytesToUInt32(md5Data[0:4])
	uidPack := binaryx.LEUint32ToBytes(uid)
	randLen := a.udpRndDataLen(md5Data, a.RandomClient)
	rc4Key := bytesx.ContactSlice(
		[]byte(base64.StdEncoding.EncodeToString(a.UserKey)),
		[]byte(base64.StdEncoding.EncodeToString(md5Data)),
	)
	encryptor, err := ciphers.NewEncryptor("rc4", string(rc4Key))
	if err != nil {
		return nil, err
	}
	result, err := encryptor.Encrypt(buf)
	if err != nil {
		return nil, err
	}
	result = bytesx.ContactSlice(result, randomx.RandomBytes(randLen), authData, uidPack)
	return bytesx.ContactSlice(result, hmacmd5(a.UserKey, result)[:1]), nil

}

func (a *AuthChainA) ClientUDPPostDecrypt(buf []byte) ([]byte, error) {
	if len(buf) < 8 {
		return []byte{}, nil
	}
	// 校验位盖在它之前的全部字节上，不匹配即丢弃
	if !bytes.Equal(hmacmd5(a.UserKey, buf[:len(buf)-1])[:1], buf[len(buf)-1:]) {
		return []byte{}, nil
	}
	macKey := a.GetServerInfo().GetKey()
	md5Data := hmacmd5(macKey, buf[len(buf)-8:len(buf)-1])
	randLen := a.udpRndDataLen(md5Data, a.RandomServer)
	rc4Key := bytesx.ContactSlice(
		[]byte(base64.StdEncoding.EncodeToString(a.UserKey)),
		[]byte(base64.StdEncoding.EncodeToString(md5Data)),
	)
	encryptor, err := ciphers.NewEncryptor("rc4", string(rc4Key))
	if err != nil {
		return nil, err
	}
	return encryptor.Decrypt(buf[:len(buf)-8-randLen])
}

func (a *AuthChainA) ServerUDPPreEncrypt(buf, uid []byte) ([]byte, error) {
	var userKey []byte
	if passwd := a.GetServerInfo().GetUsers()[string(uid)]; passwd != "" {
		userKey = []byte(passwd)
	} else if len(a.GetServerInfo().GetUsers()) == 0 {
		// 多端口：本端口自己就是账号，回包按本端口密钥封
		userKey = a.GetServerInfo().GetKey()
	} else {
		// 表上没有这个账号：换个 key 封出去只会让客户端解出垃圾，交回调用方丢弃
		return nil, errors.New("auth_chain udp response to unknown identity")
	}
	authData := randomx.RandomBytes(7)
	macKey := a.GetServerInfo().GetKey()
	md5Data := hmacmd5(macKey, authData)
	randLen := a.udpRndDataLen(md5Data, a.RandomServer)
	rc4Key := bytesx.ContactSlice(
		[]byte(base64.StdEncoding.EncodeToString(userKey)),
		[]byte(base64.StdEncoding.EncodeToString(md5Data)),
	)
	encryptor, err := ciphers.NewEncryptor("rc4", string(rc4Key))
	if err != nil {
		return nil, err
	}
	result, err := encryptor.Encrypt(buf)
	if err != nil {
		return nil, err
	}
	result = bytesx.ContactSlice(result, randomx.RandomBytes(randLen), authData)
	result = bytesx.ContactSlice(result, hmacmd5(userKey, result)[:1])
	return result, nil
}

func (a *AuthChainA) ServerUDPPostDecrypt(buf []byte) ([]byte, string, error) {
	macKey := a.GetServerInfo().GetKey()
	md5Data := hmacmd5(macKey, buf[len(buf)-8:len(buf)-5])
	uid := binaryx.LEBytesToUInt32(buf[len(buf)-5:len(buf)-1]) ^ binaryx.LEBytesToUInt32(md5Data[:4])
	uidPack := binaryx.LEUint32ToBytes(uid)
	var userKey []byte
	if passwd := a.GetServerInfo().GetUsers()[string(uidPack)]; passwd != "" {
		userKey = []byte(passwd)
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
	// 校验位盖在它之前的全部字节上，不匹配即丢弃
	if !bytes.Equal(hmacmd5(userKey, buf[:len(buf)-1])[:1], buf[len(buf)-1:]) {
		return []byte{}, "", nil
	}
	randLen := a.udpRndDataLen(md5Data, a.RandomServer)
	rc4Key := bytesx.ContactSlice(
		[]byte(base64.StdEncoding.EncodeToString(userKey)),
		[]byte(base64.StdEncoding.EncodeToString(md5Data)),
	)
	encryptor, err := ciphers.NewEncryptor("rc4", string(rc4Key))
	if err != nil {
		return nil, "", err
	}
	if len(buf)-8-randLen < 0 {
		return nil, "", errors.New("auth_chain_a buf is too short")
	}
	result, err := encryptor.Decrypt(buf[:len(buf)-8-randLen])
	if err != nil {
		return nil, "", err
	}
	return result, string(uidPack), nil
}

func (a *AuthChainA) Dispose() {
	core.GetApp().GetObfsProtocolService().Remove(string(a.SessionKey()), a.ClientID)
}

func (a *AuthChainA) trapezoidRandomFloat(d float64) float64 {
	if d == 0 {
		return randomx.Float64()
	}
	s := randomx.Float64()
	tmp := 1 - d
	return (math.Sqrt(tmp*tmp+4*d*s) - tmp) / (2 * d)
}

func (a *AuthChainA) trapezoidRandomInt(maxVal, d float64) int {
	v := a.trapezoidRandomFloat(d)
	return int(v * maxVal)
}

func (a *AuthChainA) rndDataLen(bufSize int, lastHash []byte, random *XorShift128Plus) int {
	switch a.Mode {
	case chainModeB:
		return a.rndDataLenB(bufSize, lastHash, random)
	case chainModeC:
		return a.rndDataLenC(bufSize, lastHash, random)
	case chainModeD:
		return a.rndDataLenD(bufSize, lastHash, random)
	case chainModeE, chainModeF:
		return a.rndDataLenE(bufSize, lastHash, random)
	}
	if bufSize > 1440 {
		return 0
	}
	random.InitFromBinLen(lastHash, bufSize)
	if bufSize > 1300 {
		return int(random.Next() % 31)
	}
	if bufSize > 900 {
		return int(random.Next() % 127)
	}
	if bufSize > 400 {
		return int(random.Next() % 521)
	}
	return int(random.Next() % 1021)
}

// b：两段补全表依次尝试，落不进任何桶才退回 a 的梯形分布
func (a *AuthChainA) rndDataLenB(bufSize int, lastHash []byte, random *XorShift128Plus) int {
	if bufSize >= 1440 {
		return 0
	}
	random.InitFromBinLen(lastHash, bufSize)
	target := bufSize + a.Overhead
	pos := bisectLeft(a.DataSizeList, target)
	if final := pos + int(random.Next()%uint64(len(a.DataSizeList))); final < len(a.DataSizeList) {
		return a.DataSizeList[final] - target
	}
	pos = bisectLeft(a.DataSizeList2, target)
	finalPos := pos + int(random.Next()%uint64(len(a.DataSizeList2)))
	if finalPos < len(a.DataSizeList2) {
		return a.DataSizeList2[finalPos] - target
	}
	if finalPos < pos+len(a.DataSizeList2)-1 {
		return 0
	}
	if bufSize > 1300 {
		return int(random.Next() % 31)
	}
	if bufSize > 900 {
		return int(random.Next() % 127)
	}
	if bufSize > 400 {
		return int(random.Next() % 521)
	}
	return int(random.Next() % 1021)
}

// c：单表，超过最大桶仍按 a 的分段补，桶内随机选一个
func (a *AuthChainA) rndDataLenC(bufSize int, lastHash []byte, random *XorShift128Plus) int {
	other := bufSize + a.Overhead
	random.InitFromBinLen(lastHash, bufSize)
	if other >= a.DataSizeList0[len(a.DataSizeList0)-1] {
		if other >= 1440 {
			return 0
		}
		if other > 1300 {
			return int(random.Next() % 31)
		}
		if other > 900 {
			return int(random.Next() % 127)
		}
		if other > 400 {
			return int(random.Next() % 521)
		}
		return int(random.Next() % 1021)
	}
	pos := bisectLeft(a.DataSizeList0, other)
	finalPos := pos + int(random.Next()%uint64(len(a.DataSizeList0)-pos))
	return a.DataSizeList0[finalPos] - other
}

// d：超过最大桶就不补（包长分布不再有长尾）
func (a *AuthChainA) rndDataLenD(bufSize int, lastHash []byte, random *XorShift128Plus) int {
	other := bufSize + a.Overhead
	if other >= a.DataSizeList0[len(a.DataSizeList0)-1] {
		return 0
	}
	random.InitFromBinLen(lastHash, bufSize)
	pos := bisectLeft(a.DataSizeList0, other)
	finalPos := pos + int(random.Next()%uint64(len(a.DataSizeList0)-pos))
	return a.DataSizeList0[finalPos] - other
}

// e/f：固定取最小补齐尺寸，不随机
func (a *AuthChainA) rndDataLenE(bufSize int, lastHash []byte, random *XorShift128Plus) int {
	random.InitFromBinLen(lastHash, bufSize)
	other := bufSize + a.Overhead
	if other >= a.DataSizeList0[len(a.DataSizeList0)-1] {
		return 0
	}
	pos := bisectLeft(a.DataSizeList0, other)
	return a.DataSizeList0[pos] - other
}

func (a *AuthChainA) udpRndDataLen(lastHash []byte, random *XorShift128Plus) int {
	random.InitFromBin(lastHash)
	return int(random.Next() % 127)
}

func (a *AuthChainA) rndStartPos(randLen int, random *XorShift128Plus) int {
	if randLen > 0 {
		return int(random.Next() % 8589934609 % uint64(randLen))
	}
	return 0
}

func (a *AuthChainA) rndData(bufSize int, buf []byte, lastHashe []byte, random *XorShift128Plus) []byte {
	randLen := a.rndDataLen(bufSize, lastHashe, random)
	rndDataBuf := randomx.RandomBytes(randLen)
	if bufSize == 0 {
		return rndDataBuf
	} else {
		if randLen > 0 {
			startPos := a.rndStartPos(randLen, random)
			return conbineToBytes(rndDataBuf[:startPos], buf, rndDataBuf[startPos:])
		} else {
			return buf
		}
	}
}

func (a *AuthChainA) packClientData(buf []byte) ([]byte, error) {
	buf, err := a.Encryptor.Encrypt(buf)
	if err != nil {
		return nil, err
	}
	data := a.rndData(len(buf), buf, a.LastClientHash, a.RandomClient)
	// macKey 里的 PackID 按小端 4 字节（与 packServerData 用同一个函数）：这是与参考实现一致的线格式
	macKey := bytesx.ContactSlice(a.UserKey, binaryx.LEUint32ToBytes(a.PackID))
	length := len(buf) ^ int(binaryx.LEBytesToUint16(a.LastClientHash[14:]))
	data = bytesx.ContactSlice(binaryx.LEUInt16ToBytes(uint16(length)), data)
	a.LastClientHash = hmacmd5(macKey, data)
	data = bytesx.ContactSlice(data, a.LastClientHash[:2])
	a.PackID++
	return data, nil
}

func (a *AuthChainA) packServerData(buf []byte) ([]byte, error) {
	buf, err := a.Encryptor.Encrypt(buf)
	if err != nil {
		return nil, err
	}
	data := a.rndData(len(buf), buf, a.LastServerHash, a.RandomServer)
	macKey := bytesx.ContactSlice(a.UserKey, binaryx.LEUint32ToBytes(a.PackID))
	length := len(buf) ^ int(binaryx.LEBytesToUint16(a.LastServerHash[14:]))
	data = bytesx.ContactSlice(binaryx.LEUInt16ToBytes(uint16(length)), data)
	a.LastServerHash = hmacmd5(macKey, data)
	data = bytesx.ContactSlice(data, a.LastServerHash[:2])
	a.PackID++
	return data, nil
}

func (a *AuthChainA) packAuthData(authData, buf []byte) (result []byte, err error) {
	data := authData
	data = bytesx.ContactSlice(data, binaryx.LEUInt16ToBytes(uint16(a.GetServerInfo().GetOverhead())), binaryx.LEUInt16ToBytes(0))
	macKey := bytesx.ContactSlice(a.GetServerInfo().GetIv(), a.GetServerInfo().GetKey())

	checkHead := randomx.RandomBytes(4)
	a.LastClientHash = hmacmd5(macKey, checkHead)
	checkHead = bytesx.ContactSlice(checkHead, a.LastClientHash[:8])

	param := a.GetServerInfo().GetProtocolParam()
	var uidPack []byte
	if strings.Contains(param, ":") {
		items := strings.Split(param, ":")
		if len(items) > 1 {
			a.UserKey = []byte(items[1])
			uidInt, err := strconv.Atoi(items[0])
			if err != nil {
				return nil, err
			}
			uidPack = binaryx.LEUint32ToBytes(uint32((uidInt)))
		} else {
			uidPack = randomx.RandomBytes(4)
		}
	} else {
		uidPack = randomx.RandomBytes(4)
	}

	if a.UserKey == nil {
		a.UserKey = a.GetServerInfo().GetKey()
	}

	encryptor, err := ciphers.NewEncryptorWithIv("aes-128-cbc",
		string(bytesx.ContactSlice([]byte(base64.StdEncoding.EncodeToString(a.UserKey)), a.Salt)),
		bytes.Repeat([]byte{0x00}, 16))
	if err != nil {
		return nil, err
	}

	uid := binaryx.LEBytesToUInt32([]byte{uidPack[0], uidPack[1], 0x00, 0x00}) ^ binaryx.LEBytesToUInt32(a.LastClientHash[8:12])
	uidPack = binaryx.LEUint32ToBytes(uint32(uid))
	dataCipherText, err := encryptor.Encrypt(data)
	if err != nil {
		return nil, err
	}
	data = bytesx.ContactSlice(uidPack, dataCipherText[16:])
	a.LastServerHash = hmacmd5(a.UserKey, data)
	data = bytesx.ContactSlice(checkHead, data, a.LastServerHash[:4])
	rc4Key := bytesx.ContactSlice(
		[]byte(base64.StdEncoding.EncodeToString(a.UserKey)),
		[]byte(base64.StdEncoding.EncodeToString(a.LastClientHash)),
	)
	a.Encryptor, err = ciphers.NewEncryptor("rc4", string(rc4Key))
	if err != nil {
		return nil, err
	}

	packClientData, err := a.packClientData(buf)
	if err != nil {
		return nil, err
	}
	return bytesx.ContactSlice(data, packClientData), nil
}
