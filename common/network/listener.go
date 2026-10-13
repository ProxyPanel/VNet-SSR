package network

import (
	"context"
	"errors"
	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/utils/addrx"
	"github.com/sirupsen/logrus"
	"net"
	"runtime/debug"
	"strings"
	"time"
)

func NewListener(addr string, timeout time.Duration) *Listener {
	listener := new(Listener)
	listener.Timeout = timeout
	listener.Addr = addr
	return listener
}

type Listener struct {
	Addr    string
	Timeout time.Duration
	TCP     *net.TCPListener
	UDP     net.PacketConn
	context.Context
}

func (l *Listener) ListenTCP(fn func(request *Request)) error {
	if l.Addr == "" {
		return errors.New("listener Addr is empty")
	}

	listen, err := net.Listen("tcp", l.Addr)
	if err != nil {
		return err
	}
	logrus.Infof("Listener listen on: %s", l.Addr)
	l.TCP = listen.(*net.TCPListener)
	go func() {
		defer func() {
			if e := recover(); e != nil {
				logrus.Errorf("ListenTCP crashed , err : %s , \ntrace:%s", e, string(debug.Stack()))
			}
		}()
		for {

			con, err := l.TCP.Accept()
			// 三类错误都只结束 accept 循环：未知错误不在这里重试
			if err != nil {
				errString := err.Error()
				switch {
				case strings.Contains(errString, "timeout"):
					logrus.Infof("accept conn timeout: %s", errString)
					return
				case strings.Contains(errString, " use of closed network connection"):
					logrus.Infof("service %v close", addrx.SplitPortFromAddr(l.Addr))
					return
				default:
					logrus.Errorf("listener Unknown error:%s", errString)
					return
				}
			}
			go func() {
				defer func() {
					if e := recover(); e != nil {
						logrus.WithFields(logrus.Fields{}).Errorf("connection handle crashed , err : %s , \ntrace:%s", e, string(debug.Stack()))
					}
				}()
				fn(NewRequestWithTCP(con))
			}()
		}
	}()
	return nil
}

func (l *Listener) ListenUDP(fn func(request *Request)) error {
	if l.Addr == "" {
		return errors.New("listener Addr is empty")
	}

	listen, err := net.ListenPacket("udp", l.Addr)
	if err != nil {
		return err
	}
	l.UDP = listen
	go func() {
		defer func() {
			if e := recover(); e != nil {
				logrus.Errorf("ListenUDP crashed , err : %s , \ntrace:%s", e, string(debug.Stack()))
			}
		}()
		fn(NewRequestWithUDP(l.UDP))
	}()
	return nil

}

func (l *Listener) Close() error {
	if l.TCP != nil {
		if err := l.TCP.Close(); err != nil {
			log.Error("listener close tcp error: %+v", err)
			return err
		}
		log.Info("listener %s tcp close", l.Addr)
	}

	if l.UDP != nil {
		if err := l.UDP.Close(); err != nil {
			log.Error("listener close udp error: %+v", err)
			return err
		}
		log.Info("listener %s udp close", l.Addr)
	}

	return nil
}
