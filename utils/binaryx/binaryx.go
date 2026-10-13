package binaryx

import (
	"encoding/binary"
)

func LEBytesToUint64(data []byte) uint64 {
	if len(data) < 8 {
		return 0
	}
	return binary.LittleEndian.Uint64(data)
}

func LEUInt16ToBytes(data uint16) []byte {
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, data)
	return buf
}

func LEBytesToUint16(data []byte) uint16 {
	if len(data) < 2 {
		return 0
	}
	return binary.LittleEndian.Uint16(data)
}

// 线格式的身份与长度字段一律小端（auth 包里的端口、auth_chain 的 macKey、TLS 记录的补长）：
// 编码走 LEUint32ToBytes、解码走 LEBytesToUInt32，改成大端会同时打断两侧，测试抓得到
func LEBytesToUInt32(data []byte) uint32 {
	if len(data) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(data)
}

func LEUint32ToBytes(data uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, data)
	return buf
}
