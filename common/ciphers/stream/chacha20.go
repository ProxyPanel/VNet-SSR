package stream

import (
	"crypto/cipher"

	chacha20 "gitlab.com/yawning/chacha20.git"
)

func init() {
	registerStreamCiphers("chacha20", &_chacha20{32, 8})
	registerStreamCiphers("chacha20-ietf", &_chacha20{32, 12})
}

type _chacha20 struct {
	keyLen int
	ivLen  int
}

func (a *_chacha20) KeyLen() int {
	return a.keyLen
}
func (a *_chacha20) IVLen() int {
	return a.ivLen
}

// 不用 golang.org/x/crypto/chacha20：它只收 12 字节 nonce（8 字节 IV 要靠 nonce 提升绕行），
// 且 amd64 上没有汇编（汇编只覆盖 arm64/ppc64x/s390x），实测 keystream 3532 → 705 MB/s。
// 换实现前请先跑 chacha20_golden_test.go：它拿换源前生成的 keystream 逐字节比对。
func (a *_chacha20) NewStream(key, iv []byte, _ int) (cipher.Stream, error) {
	return chacha20.New(key, iv)
}
