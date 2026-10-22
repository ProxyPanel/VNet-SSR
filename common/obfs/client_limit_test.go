package obfs

import (
	"bytes"
	"net"
	"testing"

	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/ProxyPanel/VNet-SSR/utils/binaryx"
)

// 并发客户端上限有两个入口：NodeReload 按 client_limit 落一次，protocol_param 的 max_client
// 在每次建会话时落一次。后者只有解析出整数才生效——空值不能把已设的上限拍回默认 64。
// 覆盖所有读这个字段的代际：v4 是裸整数，aes128 与 chain 六代是 max_client[#后缀]。
func TestSetServerInfoAppliesProtocolParamOnlyWhenParseable(t *testing.T) {
	for _, tc := range []struct {
		method string
		param  string
	}{
		{"auth_sha1_v4", "7"},
		{"auth_aes128_md5", "7"},
		// 「#」后是 mu 形态的用户表，不影响前段解析出的上限
		{"auth_aes128_sha1", "7#1024:killer"},
		{"auth_chain_a", "7"},
		{"auth_chain_b", "7"},
		// chain_f 的后缀是包长表轮换秒数
		{"auth_chain_f", "7#3600"},
	} {
		service := NewObfsAuthChainData(tc.method)
		core.GetApp().SetObfsProtocolService(service)
		service.SetMaxClient(200)

		s := NewServerInfo()
		s.SetKey(MustHexDecode("b36d331451a61eb2d76860e00c347396"))
		s.SetIv(MustHexDecode("271d7f17d03ed7cd1f44327456aebfa2"))
		s.SetRecvIv(MustHexDecode("271d7f17d03ed7cd1f44327456aebfa2"))
		s.SetOverhead(9)

		p, err := GetObfs(tc.method)
		if err != nil {
			t.Fatalf("%s 未注册: %v", tc.method, err)
		}
		p.SetServerInfo(s)
		if service.MaxClient != 200 {
			t.Fatalf("%s 在 protocol_param 为空时把上限冲成了 %d", tc.method, service.MaxClient)
		}

		s.SetProtocolParam(tc.param)
		p2, err := GetObfs(tc.method)
		if err != nil {
			t.Fatalf("%s 未注册: %v", tc.method, err)
		}
		p2.SetServerInfo(s)
		if service.MaxClient != 7 {
			t.Fatalf("%s 没按 protocol_param 的 max_client 生效，当前 %d", tc.method, service.MaxClient)
		}
		if c, ok := p2.(*AuthChainA); ok && c.Mode == chainModeF && c.KeyChangeInterva != 3600 {
			t.Fatalf("auth_chain_f 的轮换秒数没解析出来，当前 %d", c.KeyChangeInterva)
		}
	}
}

// 连接计数按账号分桶：多端口与 auth_sha1_v4 的 auth 包里不带账号身份，计数键取建连时下发的
// 账号身份（多端口即监听端口）。两个账号必须落进两个桶——共用一个空键会让 client_limit
// 变成全节点共享，A 账号占满就拒 B 账号的新连接
func TestSessionKeyBucketsPerAccount(t *testing.T) {
	service := NewObfsAuthChainData("auth_sha1_v4")
	core.GetApp().SetObfsProtocolService(service)
	service.SetMaxClient(64)

	newSide := func(identity uint32) *AuthSha1V4 {
		p, err := GetObfs("auth_sha1_v4")
		if err != nil {
			t.Fatalf("auth_sha1_v4 未注册: %v", err)
		}
		s := NewServerInfo()
		s.SetIdentity(binaryx.LEUint32ToBytes(identity))
		s.SetProtocolParam("64")
		s.SetKey(MustHexDecode("b36d331451a61eb2d76860e00c347396"))
		s.SetIv(MustHexDecode("271d7f17d03ed7cd1f44327456aebfa2"))
		s.SetRecvIv(MustHexDecode("271d7f17d03ed7cd1f44327456aebfa2"))
		p.SetServerInfo(s)
		return p.(*AuthSha1V4)
	}

	a, b := newSide(1001), newSide(1002)
	if bytes.Equal(a.SessionKey(), b.SessionKey()) {
		t.Fatalf("两个账号取到同一个计数键 %q", a.SessionKey())
	}
	if !service.Insert(a.SessionKey(), 1, 1) || !service.Insert(b.SessionKey(), 1, 1) {
		t.Fatal("两个账号各自的首连接都应被接受")
	}
	if len(service.Buckets) != 2 {
		t.Fatalf("计数桶数 %d, want 2", len(service.Buckets))
	}

	// 单端口下 auth 包解出身份后，计数键跟着换成包里的那个
	c := newSide(1001)
	c.UserID = binaryx.LEUint32ToBytes(2002)
	if !bytes.Equal(c.SessionKey(), binaryx.LEUint32ToBytes(2002)) {
		t.Fatalf("解出身份后计数键没换：得到 %q", c.SessionKey())
	}
}

// identityBearing 那份名单是单端口能否归属账号的依据，必须与各代际的实际行为一致：
// 标了却不在握手包里认身份的协议，会让单端口节点跑成零归属
func TestIdentityBearingNamesActuallyResolvePacketIdentity(t *testing.T) {
	type sessionKeyer interface{ SessionKey() []byte }
	uid := binaryx.LEUint32ToBytes(1024)

	names := IdentityBearingNames()
	if len(names) == 0 {
		t.Fatal("名单为空，单端口模式将无协议可用")
	}
	for _, name := range names {
		core.GetApp().SetObfsProtocolService(NewObfsAuthChainData(name))

		newSide := func() Plain {
			p, err := GetObfs(name)
			if err != nil {
				t.Fatalf("%s 未注册: %v", name, err)
			}
			s := NewServerInfo()
			s.GetUsers().Set(string(uid), "killer")
			s.SetProtocolParam("1024:killer")
			s.SetClient(net.ParseIP("127.0.0.1"))
			s.SetPort(8080)
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
		client, server := newSide(), newSide()

		encoded, err := client.ClientPreEncrypt([]byte("hello world, identity"))
		if err != nil {
			t.Fatalf("%s 客户端封装失败: %v", name, err)
		}
		if _, _, err := server.ServerPostDecrypt(encoded); err != nil {
			t.Fatalf("%s 服务端解包失败: %v", name, err)
		}
		keyer, ok := server.(sessionKeyer)
		if !ok {
			t.Fatalf("%s 没有 SessionKey，说明它没嵌入 AuthBase", name)
		}
		if !bytes.Equal(keyer.SessionKey(), uid) {
			t.Fatalf("%s 标了可携带身份，实际计数键是 %q, want %q", name, keyer.SessionKey(), uid)
		}
	}

	// 反向：不带身份的协议不能出现在名单里
	for _, name := range []string{"origin", "plain", "http_simple", "http_post", "tls1.2_ticket_auth", "auth_sha1_v4"} {
		if CarriesIdentity(name) {
			t.Fatalf("%s 不带账号身份却被标进名单，单端口校验会放过它", name)
		}
	}
}

// 连接关闭必须把计数桶里的 Ref 减回去：否则已断开的 clientID 在 LRU TTL 内仍算 active，
// 同一账号攒够 MaxClient 个不同 clientID 后，新连接会撞 "no inactive client" 拒绝握手。
// auth_chain/auth_sha1_v4 在 Dispose 里做了，auth_aes128 两代也必须同形。
func TestDisposeReleasesConnectionSlot(t *testing.T) {
	for _, method := range []string{"auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_sha1_v4"} {
		service := NewObfsAuthChainData(method)
		core.GetApp().SetObfsProtocolService(service)
		service.SetMaxClient(1)

		p, err := GetObfs(method)
		if err != nil {
			t.Fatalf("%s 未注册: %v", method, err)
		}
		s := NewServerInfo()
		s.SetIdentity(binaryx.LEUint32ToBytes(1001))
		s.SetProtocolParam("1")
		p.SetServerInfo(s)

		keyer, ok := p.(interface{ SessionKey() []byte })
		if !ok {
			t.Fatalf("%s 没有 SessionKey，说明它没嵌入 AuthBase", method)
		}
		key := keyer.SessionKey()
		if !service.Insert(key, 0, 1) {
			t.Fatalf("%s 首连接被拒", method)
		}

		p.Dispose()

		if !service.Insert(key, 1, 2) {
			t.Fatalf("%s 连接关闭后计数桶没释放，新 clientID 被拒", method)
		}
	}
}
