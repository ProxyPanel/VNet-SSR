package network

import (
	"github.com/rs/xid"
	"net"
	"time"
)

func DialTcp(addr string) (req *Request, err error) {
	conn, err := net.DialTimeout("tcp", addr,5 * time.Second)
	if err != nil {
		return nil, err
	}

	return &Request{
		ISStream:    true,
		Conn:     conn,
		RequestID:   xid.New().String(),
		RequestTime: time.Now(),
	}, nil
}
