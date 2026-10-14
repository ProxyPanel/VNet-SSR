package ciphers

import (
	"bytes"
	"testing"
)

// 分组模式在字节流上按块边界走：整块部分照常输出，不足一块的尾巴留着等下一批
// （参照实现只调 EVP_CipherUpdate、从不调 EVP_CipherFinal，可观察到的行为同样如此）。
// 任意切分都既不能 panic，也不能丢字节
func TestBlockCipherStreamsAcrossArbitraryChunks(t *testing.T) {
	original := bytes.Repeat([]byte("0123456789abcdef"), 7) // 112 字节，正好 7 块
	payload := append([]byte{}, original...)

	enc, err := NewEncryptor("aes-128-cbc", "killer")
	if err != nil {
		t.Fatalf("aes-128-cbc 建不出来: %v", err)
	}
	var ct []byte
	for _, n := range []int{5, 17, 1, 33, 56} {
		out, err := enc.Encrypt(payload[:n])
		if err != nil {
			t.Fatalf("%d 字节分片加密失败: %v", n, err)
		}
		ct = append(ct, out...)
		payload = payload[n:]
	}
	// IV 前置 16 字节 + 112 字节密文
	if len(ct) != 16+112 {
		t.Fatalf("密文总长 %d, want %d", len(ct), 16+112)
	}

	dec, err := NewEncryptor("aes-128-cbc", "killer")
	if err != nil {
		t.Fatalf("解密侧建不出来: %v", err)
	}
	var plain []byte
	rest := ct
	for _, n := range []int{3, 20, 29, 76} {
		out, err := dec.Decrypt(rest[:n])
		if err != nil {
			t.Fatalf("%d 字节分片解密失败: %v", n, err)
		}
		plain = append(plain, out...)
		rest = rest[n:]
	}
	if len(rest) != 0 {
		t.Fatalf("分片没覆盖全部密文，剩 %d 字节", len(rest))
	}
	if !bytes.Equal(plain, original) {
		t.Fatalf("回环不符：want %d 字节，得到 %d 字节", len(original), len(plain))
	}
}

// 凑不满一块的输入必须留在尾巴里等下一批：旧写法直接拿任意长度喂 CryptBlocks，
// 第一条连接的第一次读就 panic（crypto/cipher: input not full blocks）
func TestBlockCipherHoldsPartialBlockWithoutLoss(t *testing.T) {
	enc, err := NewEncryptor("aes-128-cbc", "killer")
	if err != nil {
		t.Fatal(err)
	}
	first, err := enc.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatalf("5 字节加密失败: %v", err)
	}
	// 只出 IV，正文一块都凑不满
	if len(first) != 16 {
		t.Fatalf("首个分片出了 %d 字节, want 只有 16 字节 IV", len(first))
	}

	second, err := enc.Encrypt(bytes.Repeat([]byte("x"), 11))
	if err != nil {
		t.Fatalf("续块加密失败: %v", err)
	}
	if len(second) != 16 {
		t.Fatalf("凑满一块应发出 16 字节，实际 %d", len(second))
	}
}
