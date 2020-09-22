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
func (a *_chacha20) NewStream(key, iv []byte, _ int) (cipher.Stream, error) {
	return chacha20.New(key, iv)
}
