package server

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/common"
	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/common/network"
	"github.com/ProxyPanel/VNet-SSR/common/pool"
	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/utils/binaryx"
	"github.com/ProxyPanel/VNet-SSR/utils/goroutine"
	"github.com/ProxyPanel/VNet-SSR/utils/netx"
	"github.com/ProxyPanel/VNet-SSR/utils/socksproxy"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"sync"
	"time"
)

// ShadowsocksProxy is respect shadowsocks proxy service
// it have Start and Stop method to control proxy
type ShadowsocksRProxy struct {
	Host              string `json:"host,omitempty"`
	Port              int    `json:"port,omitempty"`
	Method            string `json:"method,omitempty"`
	Password          string `json:"password,omitempty"`
	Protocol          string `json:"protocol,omitempty"`
	ProtocolParam     string `json:"protocolParam,omitempty"`
	Obfs              string `json:"obfs,omitempty"`
	ObfsParam         string `json:"obfsParam,omitempty"`
	*network.Listener `json:"-"`
	Users             map[string]string `json:"users,omitempty"`
	Status            string            `json:"status,omitempty"`
	Single            int               `json:"single,omitempty"`
	network.ILimiter
	core.HostFirewall
	common.TrafficReport `json:"-"`
	common.OnlineReport  `json:"-"`
	*ShadowsocksRArgs
}

// ShadowsocksArgs is ShadowsocksProxy arguments
type ShadowsocksRArgs struct {
	TCPSwitch string `json:"tcp_switch"`
	UDPSwitch string `json:"udp_switch"`
}

// Start tcp and udp according to the configuration
func (ssr *ShadowsocksRProxy) Start() error {
	ssr.Listener = network.NewListener(fmt.Sprintf("%s:%v", ssr.Host, ssr.Port), 5*time.Second)
	var err error
	if ssr.ShadowsocksRArgs.TCPSwitch != "false" {
		err = ssr.StartTCP()
		if err != nil {
			return err
		}
	}

	if ssr.ShadowsocksRArgs.UDPSwitch != "false" {
		err = ssr.StartUDP()
		if err != nil {
			return err
		}
	}
	return nil
}

func (ssr *ShadowsocksRProxy) StartTCP() error {
	return ssr.ListenTCP(func(request *network.Request) {
		ssrd, err := network.NewShadowsocksRDecorate(request,
			ssr.Obfs, ssr.Method,
			ssr.Password, ssr.Protocol,
			ssr.ObfsParam, ssr.ProtocolParam,
			ssr.Host, ssr.Port,
			false,
			ssr.Single,
			ssr.Users)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"requestId": request.RequestID,
				"error":     err,
			}).Error("shadowsocksr NewShadowsocksRDecorate error")
			return
		}
		ssrd.TrafficReport = ssr.TrafficReport
		ssrd.SetLimter(ssr.ILimiter)
		go func() {
			defer func() {
				if err := recover(); err != nil {
					logrus.WithFields(logrus.Fields{
						"requestId": request.RequestID,
					}).Errorf("shadowsocksr connection read error :%v stack: %s", err, string(debug.Stack()))
				}
			}()
			defer ssrd.Close()
			addr, err := socksproxy.ReadAddr(ssrd)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"requestId": ssrd.RequestID,
				}).Errorf("shadowsocksr read address error %s", err)
				return
			}
			ssr.handleStageAddr(ssrd.UID, ssrd.RemoteAddr().String(), ssrd.LocalAddr().String(), addr.String(), "tcp")
			log.Info("reslove addr success: %s requestId: %s", addr.String(), ssrd.GetRequestId())

			if ssr.HostFirewall != nil && !ssr.HostFirewall.JudgeHostWithReport(addr.GetAddress(), ssrd.UID) {
				log.Info("%s is reject", addr.String())
				body := fmt.Sprintf("%s is reject", addr.String())
				t := &http.Response{
					Status:        "200 OK",
					StatusCode:    200,
					Proto:         "HTTP/1.1",
					ProtoMajor:    1,
					ProtoMinor:    1,
					Body:          ioutil.NopCloser(bytes.NewBufferString(body)),
					ContentLength: int64(len(body)),
					Header:        make(http.Header, 0),
				}
				_ = t.Write(ssrd)
				return
			}

			req, err := network.DialTcp(addr.String())
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"requestId": ssrd.RequestID,
				}).Errorf("shadowsocksr proxy remote error %s", err)
				return
			}
			defer req.Close()
			_ = req.SetKeepAlive(true)
			_, _, err = netx.DuplexCopyTcp(ssrd, req)
			log.Debug("close %s", ssrd.RequestID)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"requestId": ssrd.RequestID,
				}).Errorf("shadowsocksr proxy process error %s", err)
				return
			}
		}()

	})
}

func (ssr *ShadowsocksRProxy) StartUDP() error {
	err := ssr.ListenUDP(func(request *network.Request) {
		go func() {
			defer func() {
				if e := recover(); e != nil {
					logrus.Errorf("shadowsocksr udp listener crashed , err : %s , \ntrace:%s", e, string(debug.Stack()))
				}
			}()
			ssrd, err := network.NewShadowsocksRDecorate(request,
				ssr.Obfs, ssr.Method,
				ssr.Password, ssr.Protocol,
				ssr.ObfsParam, ssr.ProtocolParam,
				ssr.Host, ssr.Port,
				false,
				ssr.Single,
				ssr.Users)
			ssrd.TrafficReport = ssr.TrafficReport
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"requestId": request.RequestID,
					"error":     err,
				}).Error("shadowsocksr NewShadowsocksRDecorate error")
			}
			// TODO UDP TIMEOUT
			udpMap := NewShadowsocksRUDPMap(30)
			for {
				data, uid, addr, err := ssrd.ReadFrom()
				if err != nil {
					if strings.Contains(err.Error(), " use of closed network connection") {
						logrus.WithFields(logrus.Fields{
							"port": ssr.Port,
						}).Info("udp close")
						return
					}
					logrus.WithFields(logrus.Fields{
						"err": err,
					}).Error("ShadowsocksRDecrate read udp error")
					continue
				}
				remoteAddr, err := socksproxy.SplitAddr(data)
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"requestId": ssrd.RequestID,
					}).Errorf("shadowsocksr read address error %s", err)
					continue
				}
				logrus.WithFields(logrus.Fields{
					"remoteAddr": remoteAddr.String(),
					"serverAddr": ssrd.PacketConn.LocalAddr().String(),
					"clientAddr": addr.String(),
					"uid":        binaryx.LEBytesToUInt32(uid),
				}).Info("recive udp proxy")
				data = data[len(remoteAddr.Raw):]
				remotePacketConn := udpMap.Get(addr.String())
				if remotePacketConn == nil {
					remotePacketConn = &ShadowsocksRUDPMapItem{}
					remotePacketConn.Uid = uid
					remotePacketConn.PacketConn, err = net.ListenPacket("udp", "")
					if err != nil {
						logrus.WithFields(logrus.Fields{
							"remoteAddr": remoteAddr.String(),
							"serverAddr": ssrd.PacketConn.LocalAddr().String(),
							"clientAddr": addr.String(),
							"uid":        binaryx.LEBytesToUInt32(uid),
							"err":        err,
						}).Error("shadowoscksr listenPacket udp error")
						continue
					}
					udpMap.Add(addr, ssrd, remotePacketConn)
				}
				remoteAddrResolve, err := net.ResolveUDPAddr("udp", remoteAddr.String())
				if err != nil {
					logrus.WithFields(logrus.Fields{
						"remoteAddr": remoteAddr.String(),
						"serverAddr": ssrd.PacketConn.LocalAddr().String(),
						"clientAddr": addr.String(),
						"uid":        binaryx.LEBytesToUInt32(uid),
						"err":        err,
					}).Error("shadowoscksr listenPacket udp error")
					continue
				}
				ssr.handleStageAddr(int(binaryx.LEBytesToUInt32(uid)), addr.String(), ssrd.PacketConn.LocalAddr().String(), remoteAddr.String(), "udp")

				if ssr.HostFirewall != nil && !ssr.HostFirewall.JudgeHostWithReport(addr.String(), int(binaryx.LEBytesToUInt32(uid))) {
					return
				}

				//udpMap.Add(addr, ssrd, remotePacketConn)
				_, err = remotePacketConn.WriteTo(data, remoteAddrResolve)
				if err != nil {
					if err != nil {
						logrus.WithFields(logrus.Fields{
							"remoteAddr": remoteAddr.String(),
							"serverAddr": ssrd.PacketConn.LocalAddr().String(),
							"clientAddr": addr.String(),
							"uid":        binaryx.LEBytesToUInt32(uid),
							"err":        err,
						}).Error("shadowoscksr listenPacket udp error")
						continue
					}
					//udpMap.Add(addr, ssrd, remotePacketConn)
				}
			}
		}()
	})
	return err
}

func (ssr *ShadowsocksRProxy) handleStageAddr(uid int, client, server, proxyTarget, network string) {
	if uid == 0 {
		logrus.WithFields(logrus.Fields{
			"uid":         uid,
			"client":      client,
			"server":      server,
			"proxyTarget": proxyTarget,
		}).Warn("handleStageAddr uid is 0")
		return
	}
	if ssr.OnlineReport != nil {
		ssr.OnlineReport.Online(uid, client)
	}
}

func (ssr *ShadowsocksRProxy) AddUser(uid int, password string) {
	if ssr.Users == nil {
		ssr.Users = make(map[string]string)
	}
	uidPack := binaryx.LEUint32ToBytes(uint32(uid))
	logrus.Debugf("shadowsocksr adduser uidPack: %s", hex.EncodeToString(uidPack))
	uidPackStr := string(uidPack)
	ssr.Users[uidPackStr] = password
}

func (ssr *ShadowsocksRProxy) DelUser(uid int) {
	if ssr.Users == nil {
		return
	}
	uidPack := string(binaryx.LEUint32ToBytes(uint32(uid)))
	delete(ssr.Users, uidPack)
}

func (ssr *ShadowsocksRProxy) Reload(users map[string]string) {
	ssr.Users = users
}

type ShadowsocksRUDPMapItem struct {
	net.PacketConn
	Uid []byte
}

// Packet NAT table
type ShadowsocksRUDPMap struct {
	sync.RWMutex
	m       map[string]*ShadowsocksRUDPMapItem
	timeout time.Duration
}

func NewShadowsocksRUDPMap(timeout time.Duration) *ShadowsocksRUDPMap {
	m := &ShadowsocksRUDPMap{}
	m.m = make(map[string]*ShadowsocksRUDPMapItem)
	m.timeout = timeout
	return m
}

func (m *ShadowsocksRUDPMap) Get(key string) *ShadowsocksRUDPMapItem {
	m.RLock()
	defer m.RUnlock()
	return m.m[key]
}

func (m *ShadowsocksRUDPMap) Set(key string, pc *ShadowsocksRUDPMapItem) {
	m.Lock()
	defer m.Unlock()
	m.m[key] = pc
}

func (m *ShadowsocksRUDPMap) Del(key string) *ShadowsocksRUDPMapItem {
	m.Lock()
	defer m.Unlock()

	pc, ok := m.m[key]
	if ok {
		delete(m.m, key)
		return pc
	}
	return nil
}

func (m *ShadowsocksRUDPMap) Add(client net.Addr, server *network.ShadowsocksRDecorate, remoteServer *ShadowsocksRUDPMapItem) {
	m.Set(client.String(), remoteServer)
	go goroutine.Protect(func() {
		//TODO defer recover
		_ = ShadowsocksRMapTimeCopy(server, client, remoteServer, m.timeout)
		if pc := m.Del(client.String()); pc != nil {
			_ = pc.Close()
		}
	})
}

// copy from src to dst at target with read timeout
func ShadowsocksRMapTimeCopy(dst *network.ShadowsocksRDecorate, target net.Addr, src *ShadowsocksRUDPMapItem, timeout time.Duration) error {
	buf := pool.GetBuf()
	defer pool.PutBuf(buf)
	defer func() {
		if e := recover(); e != nil {
			log.Error("panic in timedCopy:%v %s", e, string(debug.Stack()))
		}
	}()

	for {
		_ = src.SetReadDeadline(time.Now().Add(timeout * time.Second))
		n, raddr, err := src.ReadFrom(buf)
		if err != nil {
			return errors.Cause(err)
		}

		srcAddr := socksproxy.ParseAddr(raddr.String())
		srcAddrByte := srcAddr.Raw
		copy(buf[len(srcAddrByte):], buf[:n])
		copy(buf, srcAddrByte)
		err = dst.WriteTo(buf[:len(srcAddrByte)+n], src.Uid, target)

		if err != nil {
			return errors.Cause(err)
		}
	}
}
