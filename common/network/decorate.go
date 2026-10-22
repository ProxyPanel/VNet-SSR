package network

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/common"
	"github.com/ProxyPanel/VNet-SSR/common/ciphers"
	"github.com/ProxyPanel/VNet-SSR/common/obfs"
	"github.com/ProxyPanel/VNet-SSR/common/pool"
	"github.com/ProxyPanel/VNet-SSR/utils/addrx"
	"github.com/ProxyPanel/VNet-SSR/utils/binaryx"
	"github.com/sirupsen/logrus"
	"net"
	"strings"
	"sync"
	"sync/atomic"
)

// ErrUDPLimitExceeded 是 UDP 限速的丢包判据：调用方应静默丢弃，不要按解包错误刷日志
var ErrUDPLimitExceeded = errors.New("udp packet over speed limit")

// ErrUDPDrop 是协议层认证失败/短包的丢包判据：这条数据报不能归属任何账号，
// 调用方要在记账与限速之前静默丢弃，不能当成转发请求
var ErrUDPDrop = errors.New("udp packet dropped before authentication")

type ILimiter interface {
	DownLimit(int, int) error
	UpLimit(int, int) error
	AllowUp(int, int) bool
	AllowDown(int, int) bool
}

func NewShadowsocksRDecorate(request *Request, obfsMethod, cryptMethod, key, protocolMethod, obfsParam, protocolParam, host string, port int, isLocal bool, single int, users *obfs.UserTable) (ssrd *ShadowsocksRDecorate, err error) {
	if users == nil {
		users = obfs.NewUserTable()
	}
	// init essential parameters
	ssrd = &ShadowsocksRDecorate{
		Request:       request,
		ObfsParam:     obfsParam,
		ProtocolParam: protocolParam,
		Host:          host,
		Port:          port,
		ISLocal:       isLocal,
		Users:         users,
		single:        single,
		recvBuf:       new(bytes.Buffer),
	}

	// init obfs protocol encrypto component
	ssrd.obfs, err = obfs.GetObfs(obfsMethod)
	if err != nil {
		return nil, err
	}

	ssrd.protocol, err = obfs.GetObfs(protocolMethod)
	if err != nil {
		return nil, err
	}

	ssrd.encryptor, err = ciphers.NewEncryptor(cryptMethod, key)
	if err != nil {
		return nil, err
	}

	ssrd.Overhead = ssrd.obfs.GetOverhead(isLocal) + ssrd.protocol.GetOverhead(isLocal)

	// 多端口下账号身份就是监听端口，先定下来再建 serverInfo：连接计数桶要按它分
	if single != 1 {
		ssrd.Identity = port
	}

	// set serverinfo
	ssrd.obfs.SetServerInfo(ssrd.getServerInfo(true))
	ssrd.protocol.SetServerInfo(ssrd.getServerInfo(false))

	return ssrd, err
}

type ShadowsocksRDecorate struct {
	// 这两个计数器要用 atomic 读写，放在结构体最前面：32 位平台（linux-32/arm/mips/mipsle
	// 都在发布清单里）只有结构体首地址保证 8 字节对齐，挪到别的字段后面就会 panic
	// "unaligned 64-bit atomic operation"
	upload   int64
	download int64
	*Request
	// 本会话的线上身份编号（与账号一一对应），两种模式下都是端口：多端口 = 监听端口，
	// 单端口 = auth 包头 4 字节里的账号编号；
	// TrafficReport/OnlineReport/限速都拿它反查账号
	Identity      int
	Uid           int // 单端口下 auth 包认出账号后反查出的面板 uid；多端口恒为 0
	obfs          obfs.Plain
	protocol      obfs.Plain
	encryptor     *ciphers.Encryptor
	Host          string
	Port          int
	ObfsParam     string
	ProtocolParam string
	Users         *obfs.UserTable
	Overhead      int
	ISLocal       bool
	recvBuf       *bytes.Buffer
	single        int
	common.TrafficReport
	ILimiter
	// 发送方向（Write 与 Read 里的 sendback）共用同一套协议/加密/混淆状态，
	// 两个协程必须串行；UDP 的 pre/post encrypt 也共用协议实例
	sendMu     sync.Mutex
	udpProtoMu sync.Mutex
}

func (ssrd *ShadowsocksRDecorate) SetLimter(limiter ILimiter) {
	ssrd.ILimiter = limiter
}

// Close 先让协议释放连接计数，再关 socket：少了 Dispose，ClientQueue 的 Ref 只增不减
func (ssrd *ShadowsocksRDecorate) Close() error {
	if ssrd.protocol != nil {
		ssrd.protocol.Dispose()
	}
	if ssrd.Request != nil {
		return ssrd.Request.Close()
	}
	return nil
}

// PeekPlain 返回解密后已缓冲、尚未被上层读走的明文（只窥探不消耗）。
// 只应在建立转发之前调用：此后 recvBuf 由读协程独占，再窥探会与拷贝竞态
func (ssrd *ShadowsocksRDecorate) PeekPlain() []byte {
	return ssrd.recvBuf.Bytes()
}

// GetIdentity 返回本会话的线上身份编号：多端口模式下就是监听端口，单端口模式下从 auth 包的
// 4 字节字段解出（该字段按 SSR 线格式叫 "uid"，本面板约定装的是端口）
func (ssrd *ShadowsocksRDecorate) GetIdentity() int {
	return ssrd.Identity
}

// GetAccount 返回本会话计入「活跃账号数」的编号：多端口下是监听端口，单端口下是面板 uid。
// 单端口还没认出账号（含反查不到）时是 0，这条会话不计入 —— 它的字节同样进不了账
func (ssrd *ShadowsocksRDecorate) GetAccount() int {
	if ssrd.single == 1 {
		return ssrd.Uid
	}
	return ssrd.Identity
}

func (ssrd *ShadowsocksRDecorate) Read(buf []byte) (n int, err error) {
	defer func() {
		if ssrd.ILimiter != nil {
			if err := ssrd.ILimiter.UpLimit(ssrd.Identity, n); err != nil {
				logrus.Error(err)
			}
		}
	}()

	// ServerDecode return buffer_to_recv, is_need_decrypt, is_need_to_encode_and_send_back
	if ssrd.recvBuf.Len() > 0 {
		return ssrd.recvBuf.Read(buf)
	}

	bufTmp := make([]byte, 4*1024)
	n, err = ssrd.Conn.Read(bufTmp)
	if err != nil {
		return 0, err
	}
	atomic.AddInt64(&ssrd.upload, int64(n))

	data := bufTmp[:n]
	unobfsData, needDecrypt, needSendBack, err := ssrd.obfs.ServerDecode(data)
	if logrus.GetLevel() == logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{
			"requestId":    ssrd.RequestID,
			"data":         hex.EncodeToString(data),
			"unobfsData":   hex.EncodeToString(unobfsData),
			"needDecrypt":  needDecrypt,
			"needSendBack": needSendBack,
		}).Debug("shadowsocksr obfs ServerDecode")
	}

	if err != nil {
		if logrus.GetLevel() == logrus.DebugLevel {
			logrus.WithFields(logrus.Fields{
				"err": err,
			}).Debugf("ShadowsocksRDecorate obfs decrypt error.")
		}
		return 0, errors.New(fmt.Sprintf("[%s] shadowsocksr obfs decrypt error.", ssrd.RequestID))
	}

	if needSendBack {
		if err := ssrd.writeObfsSendback(); err != nil {
			return 0, err
		}
		return ssrd.Read(buf)
	}

	if needDecrypt {
		cleartext, err := ssrd.encryptor.Decrypt(unobfsData)
		if ssrd.protocol.GetServerInfo().GetRecvIv() == nil || len(ssrd.protocol.GetServerInfo().GetRecvIv()) == 0 {
			ssrd.protocol.GetServerInfo().SetRecvIv(ssrd.encryptor.IVIn)
		}
		if logrus.GetLevel() == logrus.DebugLevel {
			logrus.WithFields(logrus.Fields{
				"cleartextHexEncode": hex.EncodeToString(cleartext),
				"requestId":          ssrd.RequestID,
			}).Debug("ShadowsocksRDecorate encryptor Decrypt")
		}

		if err != nil && strings.Contains(err.Error(), "buf is too short") {
			return ssrd.Read(buf)
		}

		if err != nil {
			return 0, fmt.Errorf("%s: %w", fmt.Sprintf("[%s] ShadowsocksRDecorate obfs decrypt error.", ssrd.RequestID), err)
		}
		data = cleartext
	} else {
		data = unobfsData
	}

	data, sendback, err := ssrd.protocol.ServerPostDecrypt(data)
	if logrus.GetLevel() == logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{
			"serverPostDecryptHex": hex.EncodeToString(data),
			"sendback":             sendback,
			"requestId":            ssrd.RequestID,
		}).Debug("ShadowsocksRDecorate protocol ServerPostDecrypt")
	}
	if err != nil {
		return 0, fmt.Errorf("%s: %w", fmt.Sprintf("[%s] ShadowsocksRDecorate protocol post decrypt error.", ssrd.RequestID), err)
	}
	if sendback {
		if err := ssrd.writeProtocolSendback(); err != nil {
			return 0, err
		}
	}
	// 计数器在读写两条路径上都会被 atomic 累加，取走时也必须原子换出，否则与对端 goroutine 竞态
	if ssrd.TrafficReport != nil && ssrd.Identity != 0 {
		if uploaded := atomic.SwapInt64(&ssrd.upload, 0); uploaded != 0 {
			ssrd.TrafficReport.Upload(ssrd.Identity, uploaded)
		}
	}
	if ssrd.recvBuf.Len() == 0 && len(data) == 0 {
		return 0, nil
	}
	ssrd.recvBuf.Write(data)
	n, err = ssrd.recvBuf.Read(buf)
	return n, err
}

// writeObfsSendback 与 Write 共用 obfs 的发送状态，必须走同一把 sendMu
func (ssrd *ShadowsocksRDecorate) writeObfsSendback() error {
	ssrd.sendMu.Lock()
	defer ssrd.sendMu.Unlock()

	result, err := ssrd.obfs.ServerEncode([]byte{})
	if err != nil {
		return err
	}
	n, err := ssrd.Conn.Write(result)
	if err != nil {
		return fmt.Errorf("%s: %w", fmt.Sprintf("[%s] ShadowsocksRDecorate obfs sendback error.", ssrd.RequestID), err)
	}
	atomic.AddInt64(&ssrd.download, int64(n))
	return nil
}

// writeProtocolSendback 与 Write 共用同一套 protocol/encryptor/obfs 发送状态；
// 空帧触发的回包与下载方向的数据帧必须严格串行，否则 keystream 与帧序都会交错
func (ssrd *ShadowsocksRDecorate) writeProtocolSendback() error {
	ssrd.sendMu.Lock()
	defer ssrd.sendMu.Unlock()

	backdata, err := ssrd.protocol.ServerPreEncrypt([]byte{})
	if logrus.GetLevel() == logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{
			"backdata":  hex.EncodeToString(backdata),
			"requestId": ssrd.RequestID,
		}).Debug("shadowoscksr Read ServerPreEncrypt")
	}
	if err != nil {
		return fmt.Errorf("%s: %w", fmt.Sprintf("[%s] ShadowsocksRDecorate protocol pre encode error.", ssrd.RequestID), err)
	}
	backdata, err = ssrd.encryptor.Encrypt(backdata)
	if err != nil {
		return fmt.Errorf("%s: %w", fmt.Sprintf("[%s] ShadowsocksRDecorate encrypter encrypt error.", ssrd.RequestID), err)
	}
	if logrus.GetLevel() == logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{
			"ReadEncryptData": hex.EncodeToString(backdata),
			"requestId":       ssrd.RequestID,
		}).Debug("shadowoscksr Read Encrypt")
	}
	backdata, err = ssrd.obfs.ServerEncode(backdata)
	if err != nil {
		return fmt.Errorf("%s: %w", fmt.Sprintf("[%s] ShadowsocksRDecorate obfs service encode error.", ssrd.RequestID), err)
	}
	if logrus.GetLevel() == logrus.DebugLevel {
		logrus.WithFields(logrus.Fields{
			"ReadServerEncodeData": hex.EncodeToString(backdata),
			"requestId":            ssrd.RequestID,
		}).Debug("shadowoscksr Read ServerEncode")
	}
	n, err := ssrd.Conn.Write(backdata)
	if err != nil {
		return fmt.Errorf("%s: %w", fmt.Sprintf("[%s] ShadowsocksRDecorate obfs sendback error.", ssrd.RequestID), err)
	}
	atomic.AddInt64(&ssrd.download, int64(n))
	return nil
}

func (ssrd *ShadowsocksRDecorate) Write(buf []byte) (n int, err error) {
	defer func() {
		if ssrd.ILimiter != nil {
			if err := ssrd.ILimiter.DownLimit(ssrd.Identity, n); err != nil {
				logrus.Error(err)
			}
		}
	}()

	ssrd.sendMu.Lock()
	defer ssrd.sendMu.Unlock()

	data, err := ssrd.protocol.ServerPreEncrypt(buf)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", fmt.Sprintf("[%s] ShadowsocksRDecorate protocol service encode error.", ssrd.RequestID), err)
	}
	data, err = ssrd.encryptor.Encrypt(data)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", fmt.Sprintf("[%s] ShadowsocksRDecorate encryptor encrypt error.", ssrd.RequestID), err)
	}
	data, err = ssrd.obfs.ServerEncode(data)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", fmt.Sprintf("[%s] ShadowsocksRDecorate obfs service encode error.", ssrd.RequestID), err)
	}
	n, err = ssrd.Conn.Write(data)
	if err != nil {
		return 0, err
	}
	atomic.AddInt64(&ssrd.download, int64(n))
	// 同 upload：与 Read 那条 goroutine 共用计数器，取走必须原子换出
	if ssrd.TrafficReport != nil && ssrd.Identity != 0 {
		if downloaded := atomic.SwapInt64(&ssrd.download, 0); downloaded != 0 {
			ssrd.TrafficReport.Download(ssrd.Identity, downloaded)
		}
	}

	return len(buf), nil
}

func (ssrd *ShadowsocksRDecorate) ReadFrom() (data, uid []byte, addr net.Addr, err error) {
	// 单个数据报解不出来只该丢这一包：协议解包任何一处 panic 都会带走整个端口的 UDP 读协程
	defer func() {
		if r := recover(); r != nil {
			logrus.Errorf("udp packet decode panic, requestId: %s: %v", ssrd.RequestID, r)
			data, uid, addr, err = nil, nil, nil, errors.New("udp packet decode panic")
		}
	}()

	// 65535：SS UDP 报文本身上限是它，前面还要加 IV/obfs/protocol/AEAD 开销，
	// 用 2048 收包会让大报文在 socket 层就被砍尾，解密后拿到的是残缺数据
	p := pool.GetUDPBuf()
	defer pool.PutUDPBuf(p)
	n, addr, err := ssrd.PacketConn.ReadFrom(p)
	if err != nil {
		return nil, nil, nil, err
	}
	data, iv, err := ssrd.encryptor.DecryptAll(p[:n])
	if err != nil {
		return nil, nil, nil, err
	}
	ssrd.udpProtoMu.Lock()
	ssrd.protocol.GetServerInfo().SetIv(iv)
	result, uidPack, err := ssrd.protocol.ServerUDPPostDecrypt(data)
	ssrd.udpProtoMu.Unlock()
	if err != nil {
		return nil, nil, nil, err
	}
	// 流密码没有完整性校验：任意密文都能解出字节，协议 MAC 才是认证判据。
	// 空结果代表这条数据报没通过认证（或短到无法归属），既不能记账也不能扣限速
	if len(result) == 0 {
		return nil, nil, nil, ErrUDPDrop
	}
	// update upload traffic
	if ssrd.single == 1 && ssrd.TrafficReport != nil {
		ssrd.TrafficReport.Upload(int(binaryx.LEBytesToUInt32([]byte(uidPack))), int64(n))
	}
	if ssrd.single != 1 && ssrd.TrafficReport != nil {
		ssrd.TrafficReport.Upload(ssrd.Identity, int64(n))
		uidPack = string(binaryx.LEUint32ToBytes(uint32(ssrd.Identity)))
	}
	if ssrd.ILimiter != nil {
		identity := ssrd.Identity
		if ssrd.single == 1 {
			identity = int(binaryx.LEBytesToUInt32([]byte(uidPack)))
		}
		if !ssrd.ILimiter.AllowUp(identity, n) {
			return nil, nil, nil, ErrUDPLimitExceeded
		}
	}
	return result, []byte(uidPack), addr, err

}

func (ssrd *ShadowsocksRDecorate) WriteTo(p, uid []byte, addr net.Addr) error {
	if ssrd.ILimiter != nil && !ssrd.ILimiter.AllowDown(int(binaryx.LEBytesToUInt32([]byte(uid))), len(p)) {
		return nil
	}
	// 每个客户端的回包协程共用同一个协议实例，补长用的 RandomServer 在实例内部
	ssrd.udpProtoMu.Lock()
	data, err := ssrd.protocol.ServerUDPPreEncrypt(p, uid)
	ssrd.udpProtoMu.Unlock()
	if err != nil {
		return err
	}
	data, err = ssrd.encryptor.EncryptAll(data, ssrd.encryptor.MustNewIV())
	if err != nil {
		return err
	}
	n, err := ssrd.Request.WriteTo(data, addr)
	if ssrd.TrafficReport != nil {
		ssrd.TrafficReport.Download(int(binaryx.LEBytesToUInt32([]byte(uid))), int64(n))
	}
	return err
}

func (ssrd *ShadowsocksRDecorate) getServerInfo(isObfs bool) obfs.ServerInfo {
	serverInfo := obfs.NewServerInfo()
	serverInfo.SetHost(ssrd.Host)
	serverInfo.SetPort(ssrd.Port)
	if ssrd.Conn != nil {
		serverInfo.SetClient(net.ParseIP(addrx.GetIPFromAddr(ssrd.Conn.RemoteAddr())))
		serverInfo.SetPort(addrx.GetPortFromAddr(ssrd.Conn.RemoteAddr()))
	}
	if isObfs {
		serverInfo.SetObfsParam(ssrd.ObfsParam)
		serverInfo.SetProtocolParam("")
	} else {
		serverInfo.SetObfsParam("")
		serverInfo.SetProtocolParam(ssrd.ProtocolParam)
	}
	serverInfo.SetIv(ssrd.encryptor.IVOut)
	serverInfo.SetRecvIv([]byte{})
	serverInfo.SetKeyStr(ssrd.encryptor.KeyStr)
	serverInfo.SetKey(ssrd.encryptor.Key)
	serverInfo.SetHeadLen(obfs.DEFAULT_HEAD_LEN)
	// MSS 固定取 1460 常量：auth_chain 与 auth_aes128 的头长与补长按它算，服务端不按实测路径 MTU 调整
	serverInfo.SetTCPMss(obfs.TCP_MSS)
	serverInfo.SetBufferSize(obfs.BUF_SIZE - ssrd.Overhead)
	serverInfo.SetOverhead(ssrd.Overhead)
	serverInfo.SetUpdateUserFunc(ssrd.UpdateUser)
	serverInfo.SetUsers(ssrd.Users)
	serverInfo.SetSingle(ssrd.single)
	// 单端口下这里还是空的，等 auth 包解出身份后由会话自己带上；多端口下就是本端口
	if ssrd.Identity != 0 {
		serverInfo.SetIdentity(binaryx.LEUint32ToBytes(uint32(ssrd.Identity)))
	}
	return serverInfo
}

func (ssrd *ShadowsocksRDecorate) UpdateUser(uid []byte) {
	if ssrd.single != 1 {
		return
	}
	identity := int(binaryx.LEBytesToUInt32(uid))
	ssrd.Identity = identity
	if ssrd.TrafficReport == nil {
		return
	}
	// 添加账号是先写密码表、再写身份索引，落在这两步之间的那条连接会反查回 0：
	// 它随后上报的字节进 uid 0 桶，发送前被丢掉
	ssrd.Uid = ssrd.TrafficReport.IdentityToUid(identity)
	logrus.Infof("ShadowsocksRDecorate update uid: %v", ssrd.Uid)
}
