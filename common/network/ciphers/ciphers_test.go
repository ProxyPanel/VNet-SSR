package ciphers

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"testing"
	"time"
)

// 每包都带随机 IV/salt，两端同口令即可对称往返。
// 端口取 ephemeral、读必须带 deadline：固定端口和裸 sleep 会让这一项在 CI 上随机挂起。
func Test_Packet(t *testing.T) {
	for _, method := range []string{"aes-256-cfb", "salsa20", "chacha20-ietf-poly1305", "aes-128-gcm"} {
		t.Run(method, func(t *testing.T) {
			server := decoratePacket(t, method)
			defer server.Close()
			client := decoratePacket(t, method)
			defer client.Close()

			payload := make([]byte, 1400)
			if _, err := io.ReadFull(rand.Reader, payload); err != nil {
				t.Fatal(err)
			}

			buf := make([]byte, 4096)
			// 16/17 是 AES-CFB 的反馈块边界，历史上这里解错过
			for _, size := range []int{1, 16, 17, 63, 1400} {
				if _, err := client.WriteTo(payload[:size], server.LocalAddr()); err != nil {
					t.Fatalf("%s 发送 %d 字节失败：%s", method, size, err)
				}

				deadline := time.Now().Add(3 * time.Second)
				if err := server.SetReadDeadline(deadline); err != nil {
					t.Fatalf("%s 设置读超时失败：%s", method, err)
				}

				// 明文长度只有接收侧知道：AEAD 的 WriteTo 返回的是密文长度
				n, _, err := server.ReadFrom(buf)
				if err != nil {
					t.Fatalf("%s 接收 %d 字节失败：%s", method, size, err)
				}
				if n != size {
					t.Fatalf("%s 收到 %d 字节，应为 %d", method, n, size)
				}
				if !bytes.Equal(buf[:n], payload[:size]) {
					t.Fatalf("%s 的 %d 字节往返内容不一致", method, size)
				}
			}
		})
	}
}

func decoratePacket(t *testing.T, method string) net.PacketConn {
	t.Helper()

	raw, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败：%s", err)
	}
	conn, err := CipherPacketDecorate("test password", method, raw)
	if err != nil {
		raw.Close()
		t.Fatalf("%s 装饰失败：%s", method, err)
	}
	return conn
}
