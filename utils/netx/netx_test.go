package netx

import (
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func TestMain(m *testing.M) {
	// 被测函数本身会打日志，测试里只关心计数与级别判据
	logrus.SetOutput(io.Discard)
	m.Run()
}

func TestClassifyCopyErr(t *testing.T) {
	opDeadline := &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}

	cases := []struct {
		name string
		err  error
		want int
	}{
		{"eof", io.EOF, kindEOF},
		{"包装过的 eof", errors.Wrap(io.EOF, "read tcp"), kindEOF},
		{"unexpected eof", io.ErrUnexpectedEOF, kindUnexpectedEOF},
		{"同伴收口叫醒的读超时", os.ErrDeadlineExceeded, kindPeerClosed},
		{"OpError 包裹的读超时", opDeadline, kindPeerClosed},
		{"连接被重置", syscall.ECONNRESET, kindReset},
		{"短写", io.ErrShortWrite, kindShortWrite},
		{"未分类", errors.New("boom"), kindOther},
	}

	for _, c := range cases {
		if got := classifyCopyErr(c.err); got != c.want {
			t.Errorf("%s: classifyCopyErr=%s, 期望 %s", c.name, kindNames[got], kindNames[c.want])
		}
	}
}

// 主动 SetDeadline 叫醒另一方向产生的超时不是故障，不该占 error 样本行
func TestPeerClosedIsNotTreatedAsFault(t *testing.T) {
	if kindNeedsSample(kindPeerClosed) || kindNeedsSample(kindEOF) || kindNeedsSample(kindUnexpectedEOF) {
		t.Errorf("正常结束的原因不该留 error 样本")
	}
	for _, k := range []int{kindReset, kindShortWrite, kindOther} {
		if !kindNeedsSample(k) {
			t.Errorf("%s 该留 error 样本", kindNames[k])
		}
	}
}

func TestCopyEndSummaryCountsAndClears(t *testing.T) {
	_ = CopyEndSummary() // 清掉上一个用例可能留下的计数

	recordCopyEnd(dirUp, kindEOF, "up eof")
	recordCopyEnd(dirUp, kindEOF, "up eof")
	recordCopyEnd(dirDown, kindPeerClosed, "down closed")

	got := CopyEndSummary()
	want := "up_eof=2 down_peer_closed=1"
	if got != want {
		t.Errorf("摘要=%q, 期望 %q", got, want)
	}

	if again := CopyEndSummary(); again != "" {
		t.Errorf("取过一次之后应清零, 实际 %q", again)
	}
}

func TestCopyEndSummaryCountsActiveUIDs(t *testing.T) {
	_ = CopyEndSummary()

	markActivePort(1001)
	markActivePort(1001) // 同一账号开多条连接只算一个活跃账号
	markActivePort(1002)
	markActivePort(0) // 还没认出身份的会话不进集合

	if got, want := CopyEndSummary(), "active_uids=2"; got != want {
		t.Errorf("摘要=%q, 期望 %q", got, want)
	}

	if again := CopyEndSummary(); again != "" {
		t.Errorf("取过一次之后活跃集合应清零, 实际 %q", again)
	}
}

// 同类真异常每分钟只留一条样本行，取摘要时重新开放
func TestRealFaultSampledOncePerMinute(t *testing.T) {
	_ = CopyEndSummary()

	if !recordCopyEnd(dirDown, kindReset, "reset 1") {
		t.Errorf("同类首条该打 error 样本")
	}
	if recordCopyEnd(dirDown, kindReset, "reset 2") {
		t.Errorf("同一分钟内的第二条不该再打 error")
	}

	_ = CopyEndSummary()

	if !recordCopyEnd(dirDown, kindReset, "reset 3") {
		t.Errorf("过了一个统计窗口后应重新允许样本行")
	}
}
