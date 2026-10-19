package service

import (
	"testing"
	"time"

	"github.com/ProxyPanel/VNet-SSR/model"
)

const reportMin = int64(trafficReportMinBytes)

// 一个端口与账号的对照关系，两条判据都靠它：身份编号→uid 的反查、以及起报门槛的字节基数
func newPortUser() *SSRManager {
	s := NewShadowsocksrService()
	user := &model.UserInfo{Uid: 7, Port: 30007, Passwd: "p", Enable: 1}
	s.userTable[7] = user
	s.identityIndex[user.Port] = 7
	return s
}

func TestUploadAttributesByPortIdentity(t *testing.T) {
	s := newPortUser()

	s.Upload(30007, reportMin)
	s.Download(30007, 200)

	rows := s.ReportTraffic()
	if len(rows) != 1 {
		t.Fatalf("超过起报门槛时该上报一行, 实际 %+v", rows)
	}
	if rows[0].Uid != 7 || rows[0].Upload != reportMin || rows[0].Download != 200 {
		t.Errorf("记账结果 uid=%d up=%d down=%d, 期望 7/%d/200", rows[0].Uid, rows[0].Upload, rows[0].Download, reportMin)
	}
	if rows[0].ReportID == "" {
		t.Errorf("上报的行必须带 report_id，面板据此整批认领")
	}
}

// 把面板 uid 当身份编号传进来时字节会落到 uid 0，而 uid<=0 的增量不上报——接口形参不要写成 uid。
// 字节数取在门槛之上，否则「没上报」就说不清是哪条判据起的作用
func TestUploadWithUIDInsteadOfPortIsDropped(t *testing.T) {
	s := newPortUser()

	s.Upload(7, reportMin+1024)

	if rows := s.ReportTraffic(); len(rows) != 0 {
		t.Fatalf("传 uid 而非端口时这批字节应被丢弃, 实际 %+v", rows)
	}
	// 被丢弃的字节不该滞留在本地表里
	if len(s.traffic) != 0 {
		t.Fatalf("uid 0 的增量应直接丢掉, 本地表却留着 %+v", s.traffic)
	}
}

// 不足门槛的行留在本地继续累加，跨过去的那一轮一次性上报——历史上这里是被丢掉的
func TestBelowThresholdAccumulatesInsteadOfDropped(t *testing.T) {
	s := newPortUser()

	s.Upload(30007, reportMin/2)
	if rows := s.ReportTraffic(); len(rows) != 0 {
		t.Fatalf("不足门槛时应留到下一轮, 实际 %+v", rows)
	}
	held, ok := s.traffic[7]
	if !ok || held.Upload != reportMin/2 {
		t.Fatalf("没到门槛的字节必须留在本地, 实际 %+v", s.traffic[7])
	}

	s.Download(30007, reportMin/2+1)
	rows := s.ReportTraffic()
	if len(rows) != 1 {
		t.Fatalf("累加跨过门槛后该上报一行, 实际 %+v", rows)
	}
	if rows[0].Upload+rows[0].Download != reportMin+1 {
		t.Errorf("上报的应是两轮累计的 %d 字节, 实际 up=%d down=%d", reportMin+1, rows[0].Upload, rows[0].Download)
	}
	if len(s.trafficSince) != 0 {
		t.Errorf("行已发出，滞留计时不该还挂着: %+v", s.trafficSince)
	}
}

// 滞留到上限时不足门槛也得上报：掉线或被禁用的人剩下的尾巴不能永远停在节点上
func TestHeldTrafficFlushesAfterTimeout(t *testing.T) {
	s := newPortUser()

	s.Upload(30007, 1024)
	if rows := s.ReportTraffic(); len(rows) != 0 {
		t.Fatalf("1KiB 远不足门槛, 不该上报, 实际 %+v", rows)
	}

	// 回拨量写成绝对时长：拿 trafficReportMaxHold 自己算的话，这个上限改成任何值用例都会「通过」
	s.trafficSince[7] = time.Now().Add(-11 * time.Minute)
	rows := s.ReportTraffic()
	if len(rows) != 1 || rows[0].Upload != 1024 {
		t.Fatalf("滞留满上限后应强制上报这一行, 实际 %+v", rows)
	}
}
