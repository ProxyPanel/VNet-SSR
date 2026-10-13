package obfs

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestHmacSHA1(t *testing.T) {
	want, err := hex.DecodeString("c74b87ee2296b8c956334fc5545c639d9c2445fc")
	if err != nil {
		t.Fatal(err)
	}
	key := []byte{0x01, 0x02, 0x03, 0x04}

	if got := hmacsha1(key, key); !reflect.DeepEqual(got, want) {
		t.Fatalf("hmacsha1() = %x, want %x", got, want)
	}
}

func TestObfsTLSSniExtension(t *testing.T) {
	otls := &ObfsTLS{Plain: &plain{ServerInfo: &serverInfo{Key: []byte{0x01, 0x02, 0x03, 0x04}}}}
	want := []byte{0x0, 0x0, 0x0, 0xe, 0x0, 0xc, 0x0, 0x0, 0x9, 0x62, 0x61, 0x69, 0x64, 0x75, 0x2e, 0x63, 0x6f, 0x6d}

	if got := otls.sni("baidu.com"); !reflect.DeepEqual(got, want) {
		t.Fatalf("sni() = %x, want %x", got, want)
	}
}

// packAuthData 的线格式是 4 字节时间 + 18 字节随机 + 10 字节校验位，服务端按前 22 字节重算那 10 字节。
func TestObfsTLSPackAuthDataLayout(t *testing.T) {
	otls := &ObfsTLS{Plain: &plain{ServerInfo: &serverInfo{Key: []byte{0x01, 0x02, 0x03, 0x04}}}}
	clientID := []byte{0x11, 0x22, 0x33, 0x44}

	auth := otls.packAuthData(clientID)
	if len(auth) != 32 {
		t.Fatalf("packAuthData 长度 = %d, want 32", len(auth))
	}

	wantMAC := hmacsha1(conbineToBytes(otls.GetServerInfo().GetKey(), clientID), auth[:22])[:10]
	if !bytes.Equal(auth[22:], wantMAC) {
		t.Fatalf("校验位 = %x, want %x", auth[22:], wantMAC)
	}
}

// TestObfsTLSHandshakeRoundTrip 走 tls1.2_ticket_auth 的完整状态机：假 ClientHello → ServerHello →
// 客户端确认 → 客户端把首个数据段随 ChangeCipherSpec 一起发出 → 服务端解出明文，之后两个方向都按
// 0x17 appdata 记录 framing。这条链是互通性判据：换掉 framing 就握不上手。
func TestObfsTLSHandshakeRoundTrip(t *testing.T) {
	client, server := InitObfs(), InitObfs()
	payload := []byte{0x01, 0x02, 0x03, 0x04}

	hello, err := client.ClientEncode(payload)
	if err != nil {
		t.Fatalf("客户端首包编码失败: %s", err.Error())
	}
	if !bytes.Equal(hello[:3], []byte{0x16, 0x03, 0x01}) {
		t.Fatalf("首包不是 TLS 握手记录: %x", hello[:3])
	}

	clear, _, needSendBack, err := server.ServerDecode(hello)
	if err != nil {
		t.Fatalf("服务端解首包失败: %s", err.Error())
	}
	if len(clear) != 0 {
		t.Fatalf("握手包不该带出明文，得到 %x", clear)
	}
	if !needSendBack {
		t.Fatal("服务端解完 ClientHello 后要求回握手数据")
	}

	serverHello, err := server.ServerEncode(nil)
	if err != nil {
		t.Fatalf("服务端编码握手数据失败: %s", err.Error())
	}
	_, needClientFinish, err := client.ClientDecode(serverHello)
	if err != nil {
		t.Fatalf("客户端解服务端握手失败: %s", err.Error())
	}
	if !needClientFinish {
		t.Fatal("客户端解完握手后应回 ChangeCipherSpec")
	}

	finish, err := client.ClientEncode(nil)
	if err != nil {
		t.Fatalf("客户端编码 ChangeCipherSpec 失败: %s", err.Error())
	}
	clear, _, _, err = server.ServerDecode(finish)
	if err != nil {
		t.Fatalf("服务端解 ChangeCipherSpec 与首个数据段失败: %s", err.Error())
	}
	if !bytes.Equal(clear, payload) {
		t.Fatalf("随 ChangeCipherSpec 带出的数据 = %x, want %x", clear, payload)
	}

	// 握手完成后两个方向都是 appdata framing，大块内容必须原样往返
	big := bytes.Repeat([]byte{0x01, 0x02}, 2048)

	ciphered, err := client.ClientEncode(big)
	if err != nil {
		t.Fatalf("客户端编码数据段失败: %s", err.Error())
	}
	if ciphered[0] != 0x17 {
		t.Fatalf("数据段不是 appdata 记录，首字节 = 0x%02x", ciphered[0])
	}
	if clear, _, _, err = server.ServerDecode(ciphered); err != nil {
		t.Fatalf("服务端解数据段失败: %s", err.Error())
	}
	if !bytes.Equal(clear, big) {
		t.Fatalf("上行数据段往返后 %d 字节，原长 %d", len(clear), len(big))
	}

	if ciphered, err = server.ServerEncode(big); err != nil {
		t.Fatalf("服务端编码数据段失败: %s", err.Error())
	}
	if clear, _, err = client.ClientDecode(ciphered); err != nil {
		t.Fatalf("客户端解数据段失败: %s", err.Error())
	}
	if !bytes.Equal(clear, big) {
		t.Fatalf("下行数据段往返后 %d 字节，原长 %d", len(clear), len(big))
	}
}

func BenchmarkObfsTLSSni(b *testing.B) {
	otls := &ObfsTLS{Plain: &plain{ServerInfo: &serverInfo{Key: []byte{0x01, 0x02, 0x03, 0x04}}}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		otls.sni("baidu.com")
	}
	b.ReportAllocs()
}

// InitObfs 造一台未握手的 obfs_tls 实例，客户端与服务端两侧共用同一份 key。
func InitObfs() *ObfsTLS {
	return &ObfsTLS{
		Plain: &plain{
			ServerInfo: &serverInfo{
				Key:        []byte{0x01, 0x02, 0x03, 0x04},
				Host:       "0.0.0.0",
				Port:       3306,
				HeadLen:    30,
				TCPMss:     1460,
				BufferSize: 65535,
			},
		},
		TLSVersion:   DEFAULT_VERSION,
		ObfsAuthData: NewObfsAuthData(),
	}
}
