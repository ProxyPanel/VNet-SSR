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

	newSide := func() Plain {
		p, err := GetObfs(method)
		if err != nil {
			t.Fatalf("%s 未注册: %v", method, err)
		}
		s := NewServerInfo()
		s.GetUsers()[string(binaryx.LEUint32ToBytes(1024))] = "killer"
		s.SetPort(8080)
		s.SetProtocolParam("1024:killer")
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
	return newSide(), newSide()
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
