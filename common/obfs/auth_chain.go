package obfs

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/utils/langx"
	"math"
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
}

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
	ConnectionID   int
	MaxTimeDif     int
	Salt           []byte
	PackID         int
	RecvID         int
	UserID         []byte
	UserIDNum      int
	UserKey        []byte
	ClientOverhead int
	LastClientHash []byte
	LastServerHash []byte
	RandomClient   *XorShift128Plus
	RandomServer   *XorShift128Plus
	Encryptor      *ciphers.Encryptor
}

func NewAuthChainA(method string) (Plain, error) {
	authBase, err := NewAuthBase(method)
	if err != nil {
		return nil, err
	}
	authBase.RawTrans = false
	authBase.Overhead = 4
	authBase.NoCompatibleMethod = "auth_chain_a"
	return &AuthChainA{
		AuthBase:       authBase,
		RecvBuf:        []byte{},
		UnintLen:       2800,
		HasRecvHeader:  false,
		HasSentHeader:  false,
		ClientID:       0,
		ConnectionID:   0,
		MaxTimeDif:     60 * 60 * 24,
		Salt:           []byte("auth_chain_a"),
		PackID:         1,
		RecvID:         1,
		UserIDNum:      0,
		ClientOverhead: 4,
		LastClientHash: []byte{},
		LastServerHash: []byte{},
		RandomClient:   NewXorShift128Plus(),
		RandomServer:   NewXorShift128Plus(),
	}, nil
}

func (a *AuthChainA) GetOverhead(direction bool) int {
	return a.Overhead
}

func (a *AuthChainA) SetServerInfo(s ServerInfo) {
	a.AuthBase.SetServerInfo(s)
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
		macKey := bytesx.ContactSlice(a.UserKey, binaryx.LEUint32ToBytes(uint32(a.RecvID)))
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
		a.RecvID = (a.RecvID + 1) & 0xFFFFFFFF
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
		var uid int
		var uidPack []byte

		uid = int(binaryx.LEBytesToUInt32(a.RecvBuf[12:16]) ^ binaryx.LEBytesToUInt32(md5Data[8:12]))
		a.UserIDNum = uid
		uidPack = binaryx.LEUint32ToBytes(uint32(uid))
		if a.GetServerInfo().GetUsers()[string(uidPack)] != "" {
			a.UserID = uidPack
			a.UserKey = []byte(a.GetServerInfo().GetUsers()[string(uidPack)])
			a.GetServerInfo().UpdateUser(uidPack)
		} else {
			return []byte{}, false, errors.New(fmt.Sprintf("user %v not exist", uid))
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
		} else if core.GetApp().GetObfsProtocolService().Insert(a.UserID, int(clientId), int(connectionId)) {
			a.HasRecvHeader = true
			a.ClientID = int(clientId)
			a.ConnectionID = int(connectionId)
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
		macKey := bytesx.ContactSlice(a.UserKey, binaryx.LEUint32ToBytes(uint32(a.RecvID)))
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
		a.RecvID = (a.RecvID + 1) & 0xFFFFFFFF
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
		core.GetApp().GetObfsProtocolService().Update(a.UserID, a.ClientID, a.ConnectionID)
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
	if bytes.Equal(hmacmd5(a.UserKey, buf[:len(buf)])[:1], buf[len(buf)-1:]) {
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
	if a.GetServerInfo().GetUsers()[string(uid)] != "" {
		userKey = []byte(a.GetServerInfo().GetUsers()[string(uid)])
	} else {
		uid = nil
		if len(a.GetServerInfo().GetUsers()) == 0 {
			userKey = a.GetServerInfo().GetKey()
		} else {
			userKey = a.GetServerInfo().GetRecvIv()
		}
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
	if a.GetServerInfo().GetUsers()[string(uidPack)] != "" {
		userKey = []byte(a.GetServerInfo().GetUsers()[string(uidPack)])
	} else {
		userKey = nil
		if len(a.GetServerInfo().GetUsers()) == 0 {
			userKey = a.GetServerInfo().GetKey()
		} else {
			userKey = a.GetServerInfo().GetRecvIv()
		}
	}
	if bytes.Equal(hmacmd5(userKey, buf[:len(buf)])[:1], buf[len(buf)-1:]) {
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
	core.GetApp().GetObfsProtocolService().Remove(string(a.UserID), a.ClientID)
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
	macKey := bytesx.ContactSlice(a.UserKey, binaryx.BEUInt32ToBytes(uint32((a.PackID))))
	length := len(buf) ^ int(binaryx.LEBytesToUint16(a.LastClientHash[14:]))
	data = bytesx.ContactSlice(binaryx.LEUInt16ToBytes(uint16(length)), data)
	a.LastClientHash = hmacmd5(macKey, data)
	data = bytesx.ContactSlice(data, a.LastClientHash[:2])
	a.PackID = (a.PackID + 1) & 0xFFFFFFFF
	return data, nil
}

func (a *AuthChainA) packServerData(buf []byte) ([]byte, error) {
	buf, err := a.Encryptor.Encrypt(buf)
	if err != nil {
		return nil, err
	}
	data := a.rndData(len(buf), buf, a.LastServerHash, a.RandomServer)
	macKey := bytesx.ContactSlice(a.UserKey, binaryx.LEUint32ToBytes(uint32(a.PackID)))
	length := len(buf) ^ int(binaryx.LEBytesToUint16(a.LastServerHash[14:]))
	data = bytesx.ContactSlice(binaryx.LEUInt16ToBytes(uint16(length)), data)
	a.LastServerHash = hmacmd5(macKey, data)
	data = bytesx.ContactSlice(data, a.LastServerHash[:2])
	a.PackID = (a.PackID + 1) & 0xFFFFFFFF
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
