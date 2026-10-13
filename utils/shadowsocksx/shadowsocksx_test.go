package shadowsocksx

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// HKDF-SHA1 是 AEAD 派生 ss-subkey 的唯一路径（aes-*-gcm 与 chacha20-ietf-poly1305 都走它）。
// 输入取自 RFC 5869 附录 A.1/A.3 那一组（IKM 22 个 0x0b、salt 0x000102030405060708090a0b0c、
// info 0xf0f1f2f3f4f5f6f7f8f9、L=42）：同一组输入按 SHA-256 算就是 RFC 公布的
// 3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865，
// 本函数固定用 SHA-1，期望值 d6000ffb… 由 Go 的 x/crypto、Python 手写 HMAC 链、
// Node 的 OpenSSL hkdfSync 三方独立算得一致。派生错了不会有任何本地报错，
// 只表现为客户端与节点算出不同子密钥、每个 AEAD 连接都解不开第一个包。
func TestHKDFSHA1MatchesRFC5869Vector(t *testing.T) {
	ikm, err := hex.DecodeString("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	if err != nil {
		t.Fatal(err)
	}
	salt, err := hex.DecodeString("000102030405060708090a0b0c")
	if err != nil {
		t.Fatal(err)
	}
	info, err := hex.DecodeString("f0f1f2f3f4f5f6f7f8f9")
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("d6000ffb5b50bd3970b260017798fb9c" +
		"8df9ce2e2c16b6cd709cca07dc3cf9cf" +
		"26d6c6d750d0aaf5ac94")
	if err != nil {
		t.Fatal(err)
	}

	key := make([]byte, len(want))
	if err := HKDF_SHA1(ikm, salt, info, key); err != nil {
		t.Fatalf("HKDF_SHA1 失败: %s", err.Error())
	}
	if !bytes.Equal(key, want) {
		t.Fatalf("派生结果 = %x, want %x", key, want)
	}
}

// AEAD 实际用法：salt 是包头的随机盐，info 固定 "ss-subkey"，输出长度等于密文的 keyLen。
// 钉住长度与「同输入同输出、换 salt 就换密钥」这两条，盐被写死或 info 打错都会在这里红。
func TestHKDFSHA1ForSSSubkeyShape(t *testing.T) {
	master := bytes.Repeat([]byte{0xa1}, 32)
	salt := bytes.Repeat([]byte{0xb2}, 32)
	otherSalt := bytes.Repeat([]byte{0xb3}, 32)

	first := make([]byte, 32)
	if err := HKDF_SHA1(master, salt, []byte("ss-subkey"), first); err != nil {
		t.Fatal(err)
	}

	repeat := make([]byte, 32)
	if err := HKDF_SHA1(master, salt, []byte("ss-subkey"), repeat); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, repeat) {
		t.Fatal("同盐同 master key 派生出不同子密钥，AEAD 两端对不上")
	}

	switched := make([]byte, 32)
	if err := HKDF_SHA1(master, otherSalt, []byte("ss-subkey"), switched); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, switched) {
		t.Fatal("换盐后子密钥没变：盐没参与派生，每个包都会用同一把 key")
	}
}
