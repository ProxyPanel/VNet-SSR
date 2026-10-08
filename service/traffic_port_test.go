package service

import (
	"testing"

	"github.com/ProxyPanel/VNet-SSR/model"
)

// TrafficReport 的实现按端口反查账号，而两种模式下装饰器传进来的都是端口：
// 多端口在 NewShadowsocksRDecorate 里 UID=port，单端口在 auth 包的 4 字节字段里带的也是端口
// （obfs 用 GetUsers()[uidPack] 查密码表，键就是端口）。所以记账必须按端口成立。
func TestUploadAttributesByPort(t *testing.T) {
	s := NewShadowsocksrService()
	s.userTable[7] = &model.UserInfo{Uid: 7, Port: 30007, Passwd: "p", Enable: 1}

	s.Upload(30007, 100)
	s.Download(30007, 200)

	rows := s.ReportTraffic()
	if len(rows) != 1 {
		t.Fatalf("端口能反查到账号时该上报一行, 实际 %+v", rows)
	}
	if rows[0].Uid != 7 || rows[0].Upload != 100 || rows[0].Download != 200 {
		t.Errorf("记账结果 uid=%d up=%d down=%d, 期望 7/100/200", rows[0].Uid, rows[0].Upload, rows[0].Download)
	}
}

// 把面板 uid 当端口传进来时字节会落到 uid 0，而 uid<=0 的增量不上报 —— 接口形参叫 uid 正是这种误用的来源
func TestUploadWithUIDInsteadOfPortIsDropped(t *testing.T) {
	s := NewShadowsocksrService()
	s.userTable[7] = &model.UserInfo{Uid: 7, Port: 30007, Passwd: "p", Enable: 1}

	s.Upload(7, 100)

	if rows := s.ReportTraffic(); len(rows) != 0 {
		t.Fatalf("传 uid 而非端口时这批字节应被丢弃, 实际 %+v", rows)
	}
}
