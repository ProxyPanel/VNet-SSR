package netx

import (
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/common/network"
	"github.com/ProxyPanel/VNet-SSR/common/pool"
	"github.com/ProxyPanel/VNet-SSR/utils/goroutine"
	"github.com/ProxyPanel/VNet-SSR/utils/socksproxy"
	"github.com/pkg/errors"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

func Copy(dst,src network.IRequest) (written int64, err error){
	buf := pool.GetBuf()
	for {
		nr, er := src.Read(buf)
		//if nr == 0{
		//	log.Debug("%s n is zero ---------------------",dst.GetRequestId())
		//}
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			//if er != io.EOF {
			//	err = er
			//}
			//log.Error("%s is error ---------------------",dst.GetRequestId())
			err = er
			break
		}
	}
	pool.PutBuf(buf)
	//log.Debug("%s written %d err %v",dst.GetRequestId(),written,err)
	return written, err
}
// DuplexCopyTcp will return 3 result
// up means left connection to right connection transfer data count
// down means right connection to left connections transfer data count
// and the last result is error
func DuplexCopyTcp(left, right network.IRequest) (up, down int64, err error) {
	recordActive(left)

	type res struct {
		N   int64
		Err error
	}
	ch := make(chan res)
	defer func() {
		if e := recover(); e != nil {
			log.Error("panic in timedCopy: %v", e)
		}
	}()

	go goroutine.Protect(func() {
		n, err := Copy(right, left)
		_ = right.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
		_ = left.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
		ch <- res{n, err}
	})

	up, err = Copy(left, right)
	_ = right.SetDeadline(time.Now()) // wake up the other goroutine blocking on right
	_ = left.SetDeadline(time.Now())  // wake up the other goroutine blocking on left
	rs := <-ch

	if rs.Err != nil {
		recordCopyEnd(dirUp, classifyCopyErr(rs.Err),
			fmt.Sprintf("netx copy %s <- %s req=%s : %s", right.RemoteAddr(), left.RemoteAddr(), left.GetRequestId(), rs.Err))
	}
	if err != nil {
		recordCopyEnd(dirDown, classifyCopyErr(err),
			fmt.Sprintf("netx copy %s -> %s req=%s : %s", right.RemoteAddr(), left.RemoteAddr(), right.GetRequestId(), err))
	}
	return up, rs.N, errors.Cause(err)
}

// 连接结束原因的计数维度。DuplexCopyTcp 在一个方向收口后会主动把两侧 deadline 设到过去叫醒另一个方向，
// 所以 deadline exceeded 是「同伴已收口」而不是网络故障；把它算成故障会让每条正常连接都产出两行 error。
const (
	dirUp   = iota // 客户端 -> 上游
	dirDown        // 上游 -> 客户端
	dirCount
)

const (
	kindEOF = iota
	kindUnexpectedEOF
	kindPeerClosed
	kindReset
	kindShortWrite
	kindOther
	kindCount
)

var (
	dirNames  = [dirCount]string{"up", "down"}
	kindNames = [kindCount]string{"eof", "unexpected_eof", "peer_closed", "conn_reset", "short_write", "other"}

	copyStatsMu sync.Mutex
	copyStats   [dirCount][kindCount]int64
	// 真异常每分钟只留一条样本行，既保住告警价值又不让它淹没日志
	copySampled [kindCount]bool

	activeMu    sync.Mutex
	activePorts = map[int]struct{}{}
)

// 会话端口与账号一一对应，所以集合大小就是本分钟建立过转发的活跃账号数
// （摘要里的字段名保留 active_uids，它是给运维看的"活跃账号数"）
type sessionPort interface{ GetUserPort() int }

func markActivePort(port int) {
	if port == 0 {
		return
	}
	activeMu.Lock()
	activePorts[port] = struct{}{}
	activeMu.Unlock()
}

func recordActive(r network.IRequest) {
	if u, ok := r.(sessionPort); ok {
		markActivePort(u.GetUserPort())
	}
}

// 这些原因代表真出问题，值得在日志里留一条可定位的样本
func kindNeedsSample(kind int) bool {
	return kind == kindReset || kind == kindShortWrite || kind == kindOther
}

func classifyCopyErr(err error) int {
	switch {
	case errors.Is(err, io.EOF):
		return kindEOF
	case errors.Is(err, io.ErrUnexpectedEOF):
		return kindUnexpectedEOF
	case errors.Is(err, os.ErrDeadlineExceeded):
		return kindPeerClosed
	case errors.Is(err, syscall.ECONNRESET):
		return kindReset
	case errors.Is(err, io.ErrShortWrite):
		return kindShortWrite
	}
	return kindOther
}

// recordCopyEnd 累加一次方向收口；返回是否打了 error 级样本行
func recordCopyEnd(dir, kind int, detail string) bool {
	copyStatsMu.Lock()
	copyStats[dir][kind]++
	needSample := kindNeedsSample(kind) && !copySampled[kind]
	if needSample {
		copySampled[kind] = true
	}
	copyStatsMu.Unlock()

	if needSample {
		log.Error("%s（同类每分钟只记这一条）", detail)
		return true
	}
	log.Debug("%s", detail)
	return false
}

// CopyEndSummary 取出并清零上一分钟的收口计数与活跃集合；两者都空时返回空串，调用方据此不打日志
func CopyEndSummary() string {
	copyStatsMu.Lock()
	defer copyStatsMu.Unlock()

	activeMu.Lock()
	active := len(activePorts)
	activePorts = map[int]struct{}{}
	activeMu.Unlock()

	var total int64
	parts := make([]string, 0, dirCount*kindCount+1)
	if active > 0 {
		parts = append(parts, fmt.Sprintf("active_uids=%d", active))
	}
	for d := 0; d < dirCount; d++ {
		for k := 0; k < kindCount; k++ {
			if n := copyStats[d][k]; n > 0 {
				total += n
				parts = append(parts, fmt.Sprintf("%s_%s=%d", dirNames[d], kindNames[k], n))
			}
			copyStats[d][k] = 0
		}
	}
	for i := range copySampled {
		copySampled[i] = false
	}

	if total == 0 && active == 0 {
		return ""
	}
	return strings.Join(parts, " ")
}

// Packet NAT table
type NatMap struct {
	sync.RWMutex
	m       map[string]net.PacketConn
	timeout time.Duration
}

func NewNatMap(timeout time.Duration) *NatMap {
	m := &NatMap{}
	m.m = make(map[string]net.PacketConn)
	m.timeout = timeout
	return m
}

func (m *NatMap) Get(key string) net.PacketConn {
	m.RLock()
	defer m.RUnlock()
	return m.m[key]
}

func (m *NatMap) Set(key string, pc net.PacketConn) {
	m.Lock()
	defer m.Unlock()
	m.m[key] = pc
}

func (m *NatMap) Del(key string) net.PacketConn {
	m.Lock()
	defer m.Unlock()

	pc, ok := m.m[key]
	if ok {
		delete(m.m, key)
		return pc
	}
	return nil
}

func (m *NatMap) Add(peer net.Addr, dst, src net.PacketConn) {
	m.Set(peer.String(), src)
	go goroutine.Protect(func() {
		_ = timedCopy(dst, peer, src, m.timeout)
		if pc := m.Del(peer.String()); pc != nil {
			_ = pc.Close()
		}
	})
}

// copy from src to dst at target with read timeout
func timedCopy(dst net.PacketConn, target net.Addr, src net.PacketConn, timeout time.Duration) error {
	buf := pool.GetBuf()
	defer pool.PutBuf(buf)
	defer func() {
		if e := recover(); e != nil {
			log.Error("panic in timedCopy: %v", e)
		}
	}()

	for {
		_ = src.SetReadDeadline(time.Now().Add(timeout))
		n, raddr, err := src.ReadFrom(buf)
		if err != nil {
			return errors.Cause(err)
		}

		srcAddr := socksproxy.ParseAddr(raddr.String())
		srcAddrByte := srcAddr.Raw
		copy(buf[len(srcAddrByte):], buf[:n])
		copy(buf, srcAddrByte)
		_, err = dst.WriteTo(buf[:len(srcAddrByte)+n], target)

		if err != nil {
			return errors.Cause(err)
		}
	}
}

