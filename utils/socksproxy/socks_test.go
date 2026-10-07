// Package socksproxy implements essential parts of SOCKS protocol.
package socksproxy

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"testing"
)

// ReadAddr 在空连接上必须返回 nil 地址 + io.EOF：调用方（proxy/server 的 TCP 分支）靠这个
// 契约区分「客户端连上就断开」和「真的读到了地址」，拿到 nil 之后绝不能再解引用
func TestReadAddr_EmptyConnection(t *testing.T) {
	addr, err := ReadAddr(bytes.NewReader(nil))

	if addr != nil {
		t.Fatalf("空连接不该给出地址: %+v", addr)
	}
	if err != io.EOF {
		t.Fatalf("空连接的错误必须是 io.EOF，调用方按它静默退出: %v", err)
	}
}

func TestSocks5Addr_GetRaw(t *testing.T) {
	tests := []struct {
		name    string
		ss      *Socks5Addr
		wantRaw []byte
		wantErr bool
	}{
		{
			"aaa",
			NewSSProtocol(AtypIPv4, 3306, "127.0.0.1"),
			NewSSProtocol(AtypIPv4, 3306, "127.0.0.1").MustGetRaw(),
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRaw, err := tt.ss.GetRaw()
			if (err != nil) != tt.wantErr {
				t.Errorf("Socks5Addr.GetRaw() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotRaw, tt.wantRaw) {
				t.Errorf("Socks5Addr.GetRaw() = %v, want %v", gotRaw, tt.wantRaw)
			}
		})
	}
}

func ExampleSocks5Addr_GetRaw() {
	fmt.Printf("%v\n", NewSSProtocol(AtypIPv4, 3306, "127.0.0.1").MustGetRaw())
	ss, _ := SplitAddr(NewSSProtocol(AtypIPv4, 3306, "127.0.0.1").MustGetRaw())
	if ss == nil {
		fmt.Println("ss is null")
	}
	fmt.Printf("%v\n", ss.MustGetRaw())

	fmt.Printf("%v\n", NewSSProtocol(AtypDomainName, 3306, "baidu.com").MustGetRaw())
	ss, _ = SplitAddr(NewSSProtocol(AtypDomainName, 3306, "baidu.com").MustGetRaw())
	if ss == nil {
		fmt.Println("ss is null")
	}
	fmt.Printf("%v\n", ss.MustGetRaw())
	//Output:
	//[1 127 0 0 1 12 234]
	//[1 127 0 0 1 12 234]
	//[3 9 98 97 105 100 117 46 99 111 109 12 234]
	//[3 9 98 97 105 100 117 46 99 111 109 12 234]
}
