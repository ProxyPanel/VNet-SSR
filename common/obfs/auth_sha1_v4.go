package obfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/adler32"
	"hash/crc32"
	"math"
	"strconv"
	"time"

	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/utils/binaryx"
	"github.com/ProxyPanel/VNet-SSR/utils/bytesx"
	"github.com/ProxyPanel/VNet-SSR/utils/randomx"
)

func init() {
	registerMethod("auth_sha1_v4", NewAuthSha1V4)
}

// AuthSha1V4 是上游仍在维护的唯一 auth_sha1 代际：verify_simple/auth_simple/
// auth_sha1/auth_sha1_v2 已被参考实现因漏洞删除，不复活。
// 帧格式与 chain 系不同：长度头带 crc32 短校验，正文尾部是 adler32，随机补长自带前缀标记。
type AuthSha1V4 struct {
	*AuthBase
	RecvBuf      []byte
	UnitLen      int
	PacketCount  int
	HasSentHead  bool
	HasRecvHead  bool
	ClientID     int
	ConnectionID int
	MaxTimeDif   int
	Salt         []byte
}

func NewAuthSha1V4(method string) (Plain, error) {
	authBase, err := NewAuthBase(method)
	if err != nil {
		return nil, err
	}
	authBase.RawTrans = false
	authBase.Overhead = 4
	authBase.NoCompatibleMethod = method
	return &AuthSha1V4{
		AuthBase:   authBase,
		RecvBuf:    []byte{},
		UnitLen:    8100,
		MaxTimeDif: 60 * 60 * 24,
		Salt:       []byte("auth_sha1_v4"),
	}, nil
}

func (a *AuthSha1V4) SetServerInfo(s ServerInfo) {
	a.AuthBase.SetServerInfo(s)
	// v4 代没有「#」后缀：protocol_param 整个就是并发客户端上限。
	// 取不到整数时保留已设的值，不在每条连接上重置
	if v, err := strconv.Atoi(s.GetProtocolParam()); err == nil {
		core.GetApp().GetObfsProtocolService().SetMaxClient(v)
	}
}

// rndData 返回「补长标记 + 随机字节」：1 是单字节标记（后随 0~127 字节），
// 255 是长标记（后随 2 字节大端长度），客户端补多长就写多长，服务端按标记跳过
func (a *AuthSha1V4) rndData(bufSize int) []byte {
	if bufSize > 1200 {
		return []byte{0x01}
	}
	var rnd []byte
	if bufSize > 400 {
		rnd = randomx.RandomBytes(int(randomx.Uint8()) % 256)
	} else {
		rnd = randomx.RandomBytes(int(binary.BigEndian.Uint16(randomx.RandomBytes(2))) % 512)
	}
	if len(rnd) < 128 {
		return bytesx.ContactSlice([]byte{byte(len(rnd) + 1)}, rnd)
	}
	return bytesx.ContactSlice([]byte{0xFF}, beUint16(uint16(len(rnd)+3)), rnd)
}

// skipLen 给出补长段总长（标记 + 随机字节）
func skipLen(marker byte, head []byte) int {
	if marker < 255 {
		return int(marker)
	}
	return int(binary.BigEndian.Uint16(head[1:3]))
}

func (a *AuthSha1V4) packData(buf []byte) []byte {
	data := bytesx.ContactSlice(a.rndData(len(buf)), buf)
	dataLen := len(data) + 8
	crc := crc32.ChecksumIEEE(beUint16(uint16(dataLen))) & 0xFFFF
	data = bytesx.ContactSlice(binaryx.LEUInt16ToBytes(uint16(crc)), data)
	data = bytesx.ContactSlice(beUint16(uint16(dataLen)), data)
	return bytesx.ContactSlice(data, binaryx.LEUint32ToBytes(adler32.Checksum(data)))
}

func (a *AuthSha1V4) packAuthData(buf []byte) []byte {
	if len(buf) == 0 {
		return []byte{}
	}
	data := bytesx.ContactSlice(a.rndData(len(buf)), buf)
	dataLen := len(data) + 16
	head := beUint16(uint16(dataLen))
	crcSeed := bytesx.ContactSlice(head, a.Salt, a.GetServerInfo().GetKey())
	data = bytesx.ContactSlice(binaryx.LEUint32ToBytes(crc32.ChecksumIEEE(crcSeed)), data)
	data = bytesx.ContactSlice(head, data)
	return bytesx.ContactSlice(data, hmacsha1(
		bytesx.ContactSlice(a.GetServerInfo().GetIv(), a.GetServerInfo().GetKey()), data)[:10])
}

func (a *AuthSha1V4) ClientPreEncrypt(buf []byte) (result []byte, err error) {
	result = []byte{}
	if !a.HasSentHead {
		headSize := a.GetHeadSize(buf, 30)
		dataLen := int(math.Min(float64(len(buf)), float64(randomx.RandIntRange(0, 31)+headSize)))
		result = bytesx.ContactSlice(result, a.packAuthData(
			bytesx.ContactSlice(core.GetApp().GetObfsProtocolService().AuthData(), buf[:dataLen])))
		buf = buf[dataLen:]
		a.HasSentHead = true
	}
	for len(buf) > a.UnitLen {
		result = bytesx.ContactSlice(result, a.packData(buf[:a.UnitLen]))
		buf = buf[a.UnitLen:]
	}
	return bytesx.ContactSlice(result, a.packData(buf)), nil
}

// unpackBody 从一帧里取正文：帧 = 长度2 + crc2 + 补长段 + 正文 + adler4
func unpackBody(frame []byte) ([]byte, error) {
	if len(frame) < 7 {
		return nil, errors.New("auth_sha1_v4: frame too short")
	}
	if binary.BigEndian.Uint16(frame[:2]) >= 8192 {
		return nil, errors.New("auth_sha1_v4: over size")
	}
	if crc32.ChecksumIEEE(frame[:2])&0xFFFF != uint32(binaryx.LEBytesToUint16(frame[2:4])) {
		return nil, errors.New("auth_sha1_v4: wrong crc")
	}
	if adler32.Checksum(frame[:len(frame)-4]) != binaryx.LEBytesToUInt32(frame[len(frame)-4:]) {
		return nil, errors.New("auth_sha1_v4: wrong adler32")
	}
	skip := skipLen(frame[4], frame[4:7])
	if 4+skip > len(frame)-4 {
		return nil, errors.New("auth_sha1_v4: bad padding length")
	}
	return frame[4+skip : len(frame)-4], nil
}

func (a *AuthSha1V4) ClientPostDecrypt(buf []byte) (result []byte, err error) {
	if a.RawTrans {
		return buf, nil
	}
	a.RecvBuf = bytesx.ContactSlice(a.RecvBuf, buf)
	result = []byte{}
	for len(a.RecvBuf) > 4 {
		length := int(binary.BigEndian.Uint16(a.RecvBuf[:2]))
		if length >= 8192 || length < 7 {
			a.RawTrans = true
			a.RecvBuf = []byte{}
			return nil, errors.New("auth_sha1_v4: client data error")
		}
		if length > len(a.RecvBuf) {
			break
		}
		body, err := unpackBody(a.RecvBuf[:length])
		if err != nil {
			a.RawTrans = true
			a.RecvBuf = []byte{}
			return nil, err
		}
		result = bytesx.ContactSlice(result, body)
		a.RecvBuf = a.RecvBuf[length:]
	}
	if len(result) > 0 {
		a.PacketCount++
	}
	return result, nil
}

func (a *AuthSha1V4) ServerPreEncrypt(buf []byte) (result []byte, err error) {
	if a.RawTrans {
		return buf, nil
	}
	result = []byte{}
	for len(buf) > a.UnitLen {
		result = bytesx.ContactSlice(result, a.packData(buf[:a.UnitLen]))
		buf = buf[a.UnitLen:]
	}
	return bytesx.ContactSlice(result, a.packData(buf)), nil
}

func (a *AuthSha1V4) ServerPostDecrypt(buf []byte) (result []byte, sendback bool, err error) {
	if a.RawTrans {
		return buf, false, nil
	}
	a.RecvBuf = bytesx.ContactSlice(a.RecvBuf, buf)
	result = []byte{}
	sendback = false

	if !a.HasRecvHead {
		if len(a.RecvBuf) <= 6 {
			return []byte{}, false, nil
		}
		seed := bytesx.ContactSlice(a.RecvBuf[:2], a.Salt, a.GetServerInfo().GetKey())
		if crc32.ChecksumIEEE(seed) != uint32(binaryx.LEBytesToUInt32(a.RecvBuf[2:6])) {
			result, sendback = a.NotMatchReturn(a.RecvBuf)
			return result, sendback, nil
		}
		length := int(binary.BigEndian.Uint16(a.RecvBuf[:2]))
		if length > len(a.RecvBuf) {
			return []byte{}, false, nil
		}
		macKey := bytesx.ContactSlice(a.GetServerInfo().GetRecvIv(), a.GetServerInfo().GetKey())
		if !bytes.Equal(hmacsha1(macKey, a.RecvBuf[:length-10])[:10], a.RecvBuf[length-10:length]) {
			result, sendback = a.NotMatchReturn(a.RecvBuf)
			return result, sendback, nil
		}
		skip := skipLen(a.RecvBuf[6], a.RecvBuf[6:9])
		outBuf := a.RecvBuf[6+skip : length-10]
		if len(outBuf) < 12 {
			result, sendback = a.NotMatchReturn(a.RecvBuf)
			return result, sendback, nil
		}
		utcTime := binaryx.LEBytesToUInt32(outBuf[:4])
		clientID := int(binaryx.LEBytesToUInt32(outBuf[4:8]))
		connectionID := int(binaryx.LEBytesToUInt32(outBuf[8:12]))
		timeDif := int(int64(utcTime) - time.Now().Unix()&0xFFFFFFFF)
		if timeDif < -a.MaxTimeDif || timeDif > a.MaxTimeDif {
			result, sendback = a.NotMatchReturn(a.RecvBuf)
			return result, sendback, nil
		}
		if !core.GetApp().GetObfsProtocolService().Insert(a.SessionKey(), clientID, connectionID) {
			result, sendback = a.NotMatchReturn(a.RecvBuf)
			return result, sendback, nil
		}
		a.HasRecvHead = true
		a.ClientID = clientID
		a.ConnectionID = connectionID
		result = outBuf[12:]
		a.RecvBuf = a.RecvBuf[length:]
		sendback = true
	}

	for len(a.RecvBuf) > 4 {
		length := int(binary.BigEndian.Uint16(a.RecvBuf[:2]))
		if length >= 8192 || length < 7 {
			a.RawTrans = true
			a.RecvBuf = []byte{}
			if a.PacketCount == 0 {
				return bytes.Repeat([]byte{byte('E')}, 2048), false, nil
			}
			return nil, false, errors.New("auth_sha1_v4: server data error")
		}
		if length > len(a.RecvBuf) {
			break
		}
		body, err := unpackBody(a.RecvBuf[:length])
		if err != nil {
			a.RawTrans = true
			a.RecvBuf = []byte{}
			if a.PacketCount == 0 {
				return bytes.Repeat([]byte{byte('E')}, 2048), false, nil
			}
			return nil, false, err
		}
		result = bytesx.ContactSlice(result, body)
		a.RecvBuf = a.RecvBuf[length:]
		if len(body) == 0 {
			sendback = true
		}
	}

	if len(result) > 0 {
		core.GetApp().GetObfsProtocolService().Update(a.SessionKey(), a.ClientID, a.ConnectionID)
		a.PacketCount++
	}
	return result, sendback, nil
}

func (a *AuthSha1V4) Dispose() {
	if service := core.GetApp().GetObfsProtocolService(); service != nil {
		service.Remove(string(a.SessionKey()), a.ClientID)
	}
}

func beUint16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}
