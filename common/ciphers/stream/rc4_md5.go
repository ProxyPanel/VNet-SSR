package stream

import (
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
)

func init() {
	registerStreamCiphers("rc4-md5", &rc4_md5{16, 16})
	registerStreamCiphers("rc4-md5-6", &rc4_md5{16, 6})
}

type rc4_md5 struct {
	keyLen int
	ivLen  int
}

func (a *rc4_md5) KeyLen() int {
	return a.keyLen
}
func (a *rc4_md5) IVLen() int {
	return a.ivLen
}
func (a *rc4_md5) NewStream(key, iv []byte, _ int) (cipher.Stream, error) {
	h := md5.New()
	h.Write(key)
	h.Write(iv)
	rc4key := h.Sum(nil)

	return rc4.NewCipher(rc4key)
}
