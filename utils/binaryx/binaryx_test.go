package binaryx

import (
	"bytes"
	"testing"
)

func TestLittleEndianEncodings(t *testing.T) {
	if got := LEUInt16ToBytes(0x0102); !bytes.Equal(got, []byte{0x02, 0x01}) {
		t.Fatalf("LEUint16ToBytes(0x0102) = %x, want 0201", got)
	}
	if got := LEUint32ToBytes(0x01020304); !bytes.Equal(got, []byte{0x04, 0x03, 0x02, 0x01}) {
		t.Fatalf("LEUint32ToBytes = %x, want 04030201", got)
	}

	if got := LEBytesToUint16([]byte{0x02, 0x01}); got != 0x0102 {
		t.Fatalf("LEBytesToUint16 = %#04x, want 0102", got)
	}
	if got := LEBytesToUInt32([]byte{0x04, 0x03, 0x02, 0x01}); got != 0x01020304 {
		t.Fatalf("LEBytesToUInt32 = %#010x, want 01020304", got)
	}
	if got := LEBytesToUint64([]byte{8, 7, 6, 5, 4, 3, 2, 1}); got != 0x0102030405060708 {
		t.Fatalf("LEBytesToUint64 = %#018x, want 0102030405060708", got)
	}
}

// 线格式里这些字段就是定长的：长度不够时返回 0 而不是 panic，
// 但调用方不能把 0 当成「对端真的发了 0」——auth 包被截断时会走这条
func TestShortInputReadsAsZero(t *testing.T) {
	if got := LEBytesToUint16([]byte{0x01}); got != 0 {
		t.Fatalf("2 字节以下应回 0, got %d", got)
	}
	if got := LEBytesToUInt32([]byte{0x01, 0x02, 0x03}); got != 0 {
		t.Fatalf("4 字节以下应回 0, got %d", got)
	}
	if got := LEBytesToUint64(bytes.Repeat([]byte{1}, 7)); got != 0 {
		t.Fatalf("8 字节以下应回 0, got %d", got)
	}
}

// auth_chain 的 macKey 直接拼 LEUint32ToBytes(PackID)，与 packServerData 用的是同一个函数：
// 这是与参考实现一致的线格式。把 LEUint32ToBytes 改成大端时，这条逐字节判据与 auth_chain、
// auth_aes128 的回环会一起红（编码走 LEUint32ToBytes、解码走 LEBytesToUInt32，两端不对称）——
// 实测过这个变异，所以这里只钉字节序本身
func TestLEUint32ToBytesIsTheWireFormat(t *testing.T) {
	cases := map[uint32][]byte{
		0:          {0x00, 0x00, 0x00, 0x00},
		1:          {0x01, 0x00, 0x00, 0x00},
		8388:       {0xc4, 0x20, 0x00, 0x00},
		0x01020304: {0x04, 0x03, 0x02, 0x01},
		0xffffffff: {0xff, 0xff, 0xff, 0xff},
	}

	for value, want := range cases {
		got := LEUint32ToBytes(value)
		if !bytes.Equal(got, want) {
			t.Fatalf("%#010x 编成 %x, want %x", value, got, want)
		}
		// 编回去必须是同一个值，否则 auth 包里的端口与密码表的键对不上
		if back := LEBytesToUInt32(got); back != value {
			t.Fatalf("%x 解回 %#010x, want %#010x", got, back, value)
		}
	}
}
