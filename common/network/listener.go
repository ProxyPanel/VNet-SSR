package network

import (
	"context"
	"errors"
	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/utils/addrx"
	"github.com/sirupsen/logrus"
	"net"
	"runtime/debug"
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
			if err != nil {
				switch {
				case errors.Is(err, net.ErrClosed):
					logrus.Infof("service %v close", addrx.SplitPortFromAddr(l.Addr))
					return
				case isTimeout(err):
					logrus.Infof("accept conn timeout: %s", err.Error())
					return
				case isTemporary(err):
					// EMFILE/ENFILE/ECONNABORTED 等是瞬时错误：退避后继续 accept，
					// 直接 return 会让端口一直绑着却再不接受连接
					logrus.Errorf("listener temporary accept error: %s", err.Error())
					time.Sleep(100 * time.Millisecond)
					continue
				default:
					logrus.Errorf("listener Unknown error:%s", err.Error())
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
	var firstErr error
	if l.TCP != nil {
		if err := l.TCP.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Error("listener close tcp error: %+v", err)
			firstErr = err
		}
		log.Info("listener %s tcp close", l.Addr)
	}

	if l.UDP != nil {
		if err := l.UDP.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			log.Error("listener close udp error: %+v", err)
			if firstErr == nil {
				firstErr = err
			}
		}
		log.Info("listener %s udp close", l.Addr)
	}

	return firstErr
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func isTemporary(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Temporary()
}
