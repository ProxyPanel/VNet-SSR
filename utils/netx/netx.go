package netx

import (
	"errors"
	"fmt"
	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/common/network"
	"github.com/ProxyPanel/VNet-SSR/common/pool"
	"github.com/ProxyPanel/VNet-SSR/utils/goroutine"
	"io"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

func Copy(dst, src network.IRequest) (written int64, err error) {
	buf := pool.GetBuf()
	for {
		nr, er := src.Read(buf)
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
			err = er
			break
		}
	}
	pool.PutBuf(buf)
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
	return up, rs.N, err
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

	// 会话账号编号与账号一一对应（多端口下是监听端口、单端口下是面板 uid），
	// 所以集合大小就是本分钟建立过转发的活跃账号数
	// （摘要里的字段名保留 active_uids，它是给运维看的"活跃账号数"）
	activeMu       sync.Mutex
	activeAccounts = map[int]struct{}{}
)

type sessionAccount interface{ GetAccount() int }

func markActiveAccount(account int) {
	if account == 0 {
		return
	}
	activeMu.Lock()
	activeAccounts[account] = struct{}{}
	activeMu.Unlock()
}

func recordActive(r network.IRequest) {
	if a, ok := r.(sessionAccount); ok {
		markActiveAccount(a.GetAccount())
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
	active := len(activeAccounts)
	activeAccounts = map[int]struct{}{}
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
