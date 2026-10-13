package service

import (
	"testing"

	"github.com/ProxyPanel/VNet-SSR/model"
)

// TrafficReport 的实现按线上身份编号反查账号，编号两种模式下都是端口：
// 多端口下会话身份就是监听端口，单端口下 auth 包头 4 字节装的也是端口（面板建号时保证全局唯一）。
func TestUploadAttributesByPortIdentity(t *testing.T) {
	s := NewShadowsocksrService()
	user := &model.UserInfo{Uid: 7, Port: 30007, Passwd: "p", Enable: 1}
	s.userTable[7] = user
	s.identityIndex[user.Port] = 7

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

// 把面板 uid 当身份编号传进来时字节会落到 uid 0，而 uid<=0 的增量不上报——接口形参不要写成 uid
func TestUploadWithUIDInsteadOfPortIsDropped(t *testing.T) {
	s := NewShadowsocksrService()
	user := &model.UserInfo{Uid: 7, Port: 30007, Passwd: "p", Enable: 1}
	s.userTable[7] = user
	s.identityIndex[user.Port] = 7

	s.Upload(7, 100)

	if rows := s.ReportTraffic(); len(rows) != 0 {
		t.Fatalf("传 uid 而非端口时这批字节应被丢弃, 实际 %+v", rows)
	}
}
