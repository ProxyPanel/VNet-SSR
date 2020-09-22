package stream

import (
	"crypto/cipher"
)

type noneStream struct{
}

func newNoneStream() (cipher.Stream,error){
	return &noneStream{},nil
}

func (noneStream *noneStream) XORKeyStream(dst, src []byte){
	copy(dst,src)
}


func init() {
	registerStreamCiphers("none", &none{16, 0})
}


type none struct {
	keyLen int
	ivLen  int
}

func (a *none) KeyLen() int {
	return a.keyLen
}
func (a *none) IVLen() int {
	return a.ivLen
}

func (a *none) NewStream(key, iv []byte, _ int) (cipher.Stream, error) {
	stream, err := newNoneStream()
	if err != nil {
		return nil, err
	}
	return stream, nil
}
