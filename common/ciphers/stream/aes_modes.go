package stream

import (
	"crypto/aes"
	"crypto/cipher"
)

func init() {
	registerStreamCiphers("aes-128-cfb1", &aes_mode{16, 16, modeCFB1})
	registerStreamCiphers("aes-192-cfb1", &aes_mode{24, 16, modeCFB1})
	registerStreamCiphers("aes-256-cfb1", &aes_mode{32, 16, modeCFB1})
	registerStreamCiphers("aes-128-cfb8", &aes_mode{16, 16, modeCFB8})
	registerStreamCiphers("aes-192-cfb8", &aes_mode{24, 16, modeCFB8})
	registerStreamCiphers("aes-256-cfb8", &aes_mode{32, 16, modeCFB8})
	registerStreamCiphers("aes-128-ofb", &aes_mode{16, 16, modeOFB})
	registerStreamCiphers("aes-192-ofb", &aes_mode{24, 16, modeOFB})
	registerStreamCiphers("aes-256-ofb", &aes_mode{32, 16, modeOFB})
}

const (
	modeCFB1 = iota
	modeCFB8
	modeOFB
)

type aes_mode struct {
	keyLen int
	ivLen  int
	mode   int
}

func (a *aes_mode) KeyLen() int { return a.keyLen }
func (a *aes_mode) IVLen() int  { return a.ivLen }

func (a *aes_mode) NewStream(key, iv []byte, decryptOrEncrypt int) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	switch a.mode {
	case modeCFB1:
		return newCFB1(block, iv, decryptOrEncrypt == 1), nil
	case modeCFB8:
		return newCFB8(block, iv, decryptOrEncrypt == 1), nil
	default:
		return cipher.NewOFB(block, iv), nil
	}
}

// cfb8 是 OpenSSL EVP 的 8 位反馈 CFB：每字节只取密钥流的最高位字节，
// 反馈寄存器左移一字节再补入密文字节（解密方向补入输入字节）。
// stdlib 的 CFB 是全段反馈，语义不同，必须自写。
type cfb8 struct {
	block    cipher.Block
	reg      []byte
	buf      []byte
	decrypt  bool
}

func newCFB8(block cipher.Block, iv []byte, decrypt bool) cipher.Stream {
	return &cfb8{block: block, reg: append([]byte{}, iv...), buf: make([]byte, block.BlockSize()), decrypt: decrypt}
}

func (s *cfb8) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		s.block.Encrypt(s.buf, s.reg)
		c := src[i] ^ s.buf[0]
		copy(s.reg, s.reg[1:])
		if s.decrypt {
			s.reg[len(s.reg)-1] = src[i]
		} else {
			s.reg[len(s.reg)-1] = c
		}
		dst[i] = c
	}
}

// cfb1 按位反馈：每比特取密钥流字节的最高位，反馈寄存器整体（128 位）左移一格
// 补入密文比特（解密方向补入输入比特）。比特在字节内按最高位在前排列，与 OpenSSL 的打包一致。
type cfb1 struct {
	block   cipher.Block
	reg     []byte
	buf     []byte
	decrypt bool
}

func newCFB1(block cipher.Block, iv []byte, decrypt bool) cipher.Stream {
	return &cfb1{block: block, reg: append([]byte{}, iv...), buf: make([]byte, block.BlockSize()), decrypt: decrypt}
}

func (s *cfb1) XORKeyStream(dst, src []byte) {
	for i := 0; i < len(src); i++ {
		out := byte(0)
		for bit := 7; bit >= 0; bit-- {
			s.block.Encrypt(s.buf, s.reg)
			c := byte(((src[i] >> bit) & 1) ^ ((s.buf[0] >> 7) & 1))
			fb := c
			if s.decrypt {
				fb = (src[i] >> bit) & 1
			}
			s.reg[0] = (s.reg[0] << 1) & 0xFF
			for j := 1; j < len(s.reg); j++ {
				carry := s.reg[j] >> 7
				s.reg[j] = (s.reg[j] << 1) & 0xFF
				s.reg[j-1] |= carry
			}
			s.reg[len(s.reg)-1] |= fb
			out |= c << bit
		}
		dst[i] = out
	}
}
