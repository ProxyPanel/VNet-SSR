package obfs

import (
	"bytes"
	"testing"

	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/utils/binaryx"
)

func newChainPair(t *testing.T, method string) (Plain, Plain) {
	t.Helper()
	core.GetApp().SetObfsProtocolService(NewObfsAuthChainData(method))

	users := map[string]string{string(binaryx.LEUint32ToBytes(1024)): "killer"}
	return newChainSide(t, method, users, "1024:killer"), newChainSide(t, method, users, "1024:killer")
}

// users 与 param 决定这一端怎么认账号：单端口靠表里的身份编号配 uid:passwd，
// 多端口表恒空、param 不带冒号
func newChainSide(t *testing.T, method string, users map[string]string, param string) Plain {
	t.Helper()
	p, err := GetObfs(method)
	if err != nil {
		t.Fatalf("%s 未注册: %v", method, err)
	}
	s := NewServerInfo()
	for uidPack, passwd := range users {
		s.GetUsers()[uidPack] = passwd
	}
	s.SetPort(8080)
	s.SetProtocolParam(param)
	s.SetIv(MustHexDecode("271d7f17d03ed7cd1f44327456aebfa2"))
	s.SetRecvIv(MustHexDecode("271d7f17d03ed7cd1f44327456aebfa2"))
	s.SetKeyStr("killer")
	s.SetKey(MustHexDecode("b36d331451a61eb2d76860e00c347396"))
	s.SetHeadLen(30)
	s.SetTCPMss(1460)
	s.SetBufferSize(32*1024 - 5 - 4)
	s.SetOverhead(9)
	p.SetServerInfo(s)
	return p
}

// 多端口节点：密码表恒空，两端都按本端口密钥算会话 key，包里的身份编号随包随机。
// 这条通路必须能完成握手，否则多端口节点上 auth_* 协议一条 TCP 也建不起来
func TestAuthChainMultiPortEmptyTableRoundTrip(t *testing.T) {
	for _, method := range []string{"auth_chain_a", "auth_chain_b", "auth_chain_f"} {
		core.GetApp().SetObfsProtocolService(NewObfsAuthChainData(method))
		empty := map[string]string{}
		client := newChainSide(t, method, empty, "64")
		server := newChainSide(t, method, empty, "64")
		payload := bytes.Repeat([]byte("m"), 300)

		encoded, err := client.ClientPreEncrypt(payload)
		if err != nil {
			t.Fatalf("%s 客户端封装失败: %v", method, err)
		}
		decoded, _, err := server.ServerPostDecrypt(encoded)
		if err != nil {
			t.Fatalf("%s 多端口空表下服务端解包失败: %v", method, err)
		}
		if !bytes.Equal(decoded, payload) {
			t.Fatalf("%s 多端口回环不符：payload %d 字节，解出 %d 字节", method, len(payload), len(decoded))
		}
	}
}

// 单端口下不认识的线上身份：没有 key 能验证这条流，按握手不匹配收尾，
// 不抛错也不把明文放出去
func TestAuthChainUnknownIdentityFailsQuietly(t *testing.T) {
	core.GetApp().SetObfsProtocolService(NewObfsAuthChainData("auth_chain_a"))
	known := map[string]string{string(binaryx.LEUint32ToBytes(1024)): "killer"}
	client := newChainSide(t, "auth_chain_a", known, "9999:killer")
	server := newChainSide(t, "auth_chain_a", known, "1024:killer")

	payload := bytes.Repeat([]byte("m"), 60)
	encoded, err := client.ClientPreEncrypt(payload)
	if err != nil {
		t.Fatalf("客户端封装失败: %v", err)
	}
	decoded, _, err := server.ServerPostDecrypt(encoded)
	if err != nil {
		t.Fatalf("不认识的身份不该抛错: %v", err)
	}
	if bytes.Contains(decoded, payload) {
		t.Fatal("不认识的身份解出了明文，密码表判据没起作用")
	}
}

// 五个变体的差异全在包长补全表；回环必须逐字节还原，否则说明两端算出的表不一致
func TestAuthChainVariantsRoundTrip(t *testing.T) {
	for _, method := range []string{"auth_chain_a", "auth_chain_b", "auth_chain_c", "auth_chain_d", "auth_chain_e", "auth_chain_f"} {
		payload := bytes.Repeat([]byte("m"), 500)
		padded := false
		for round := 0; round < 20; round++ {
			client, server := newChainPair(t, method)
			encoded, err := client.ClientPreEncrypt(payload)
			if err != nil {
				t.Fatalf("%s 客户端封装失败: %v", method, err)
			}
			decoded, _, err := server.ServerPostDecrypt(encoded)
			if err != nil {
				t.Fatalf("%s 服务端解包失败: %v", method, err)
			}
			if !bytes.Equal(decoded, payload) {
				t.Fatalf("%s 回环不符：payload %d 字节，解出 %d 字节", method, len(payload), len(decoded))
			}
			// auth 头 36 字节 + 包长 2 + 校验 2；比这个下限大就说明补了长
			if len(encoded) > 36+2+len(payload)+2+4 {
				padded = true
			}
		}
		if !padded {
			t.Fatalf("%s 二十次都没触发补长，测试没覆盖到变体差异", method)
		}
	}
}

// b/c/d/e/f 的表由 key 派生：同一 key 两端必须算出同一张表
func TestAuthChainSizeListsDeriveFromKey(t *testing.T) {
	client, server := newChainPair(t, "auth_chain_b")
	c, s := client.(*AuthChainA), server.(*AuthChainA)
	if len(c.DataSizeList) != len(s.DataSizeList) || len(c.DataSizeList2) != len(s.DataSizeList2) {
		t.Fatalf("b 的补全表两端长度不一致: %d/%d vs %d/%d",
			len(c.DataSizeList), len(c.DataSizeList2), len(s.DataSizeList), len(s.DataSizeList2))
	}
	for i := range c.DataSizeList {
		if c.DataSizeList[i] != s.DataSizeList[i] {
			t.Fatal("b 的 data_size_list 两端不一致")
		}
	}

	for _, method := range []string{"auth_chain_c", "auth_chain_d", "auth_chain_e", "auth_chain_f"} {
		client, server := newChainPair(t, method)
		c, s := client.(*AuthChainA), server.(*AuthChainA)
		if len(c.DataSizeList0) != len(s.DataSizeList0) {
			t.Fatalf("%s 表长不一致", method)
		}
		for i := range c.DataSizeList0 {
			if c.DataSizeList0[i] != s.DataSizeList0[i] {
				t.Fatalf("%s 表内容不一致", method)
			}
		}
		// d/e/f 的补丁判据保证最大桶不低于 1300，否则长包永远进不了补全分支
		if method != "auth_chain_c" && c.DataSizeList0[len(c.DataSizeList0)-1] < 1300 && len(c.DataSizeList0) >= 64 {
			t.Fatalf("%s 表在最大桶 <1300 时长度已到 64，补丁逻辑失效", method)
		}
	}
}

// f 的包长表钉在时间桶上：建连时两端各自按当前桶建表，服务端收到 auth 头后按包头时间重算，
// 同一秒内建连的两侧必须得到同一张表，否则补长判据两端不一致
func TestAuthChainFBothSidesShareRotatedTable(t *testing.T) {
	client, server := newChainPair(t, "auth_chain_f")
	c, s := client.(*AuthChainA), server.(*AuthChainA)
	if c.keyChangeDatetimeKey == 0 || s.keyChangeDatetimeKey == 0 {
		t.Fatal("f 建连时两端都应按当前桶建表")
	}

	payload := bytes.Repeat([]byte("z"), 800)
	encoded, err := client.ClientPreEncrypt(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.ServerPostDecrypt(encoded); err != nil {
		t.Fatal(err)
	}

	if len(c.DataSizeList0) != len(s.DataSizeList0) {
		t.Fatalf("服务端重算后表长变了：%d vs %d", len(c.DataSizeList0), len(s.DataSizeList0))
	}
	for i := range c.DataSizeList0 {
		if c.DataSizeList0[i] != s.DataSizeList0[i] {
			t.Fatal("服务端按包头时间重算后与客户端表不一致")
		}
	}
}
