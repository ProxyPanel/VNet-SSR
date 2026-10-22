package pool

import "sync"

const (
	BufferSize = 4096
	// UDP_MAX_PACKET_SIZE 是单个 UDP 数据报的上限；UDP 转发必须按它收，4096 会把大响应静默截尾
	UDP_MAX_PACKET_SIZE = 65535
)

var (
	tcpPool = sync.Pool{New: func() interface{} { return make([]byte, BufferSize) }}
	udpPool = sync.Pool{New: func() interface{} { return make([]byte, UDP_MAX_PACKET_SIZE) }}
)

func GetBuf() []byte {
	return tcpPool.Get().([]byte)
}

func PutBuf(buf []byte) {
	if cap(buf) == BufferSize {
		tcpPool.Put(buf[:BufferSize])
	}
}

func GetUDPBuf() []byte {
	return udpPool.Get().([]byte)
}

func PutUDPBuf(buf []byte) {
	if cap(buf) == UDP_MAX_PACKET_SIZE {
		udpPool.Put(buf[:UDP_MAX_PACKET_SIZE])
	}
}
