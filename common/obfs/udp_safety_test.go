package obfs

import (
	"testing"

	"github.com/ProxyPanel/VNet-SSR/core"
)

// 未认证的 UDP 数据报在长度不足协议头时必须在解包入口被拒绝：
// 切片越界发生在任何身份校验之前，且 StartUDP 的 recover 会带走整个端口的读协程
func TestServerUDPPostDecryptRejectsShortPayload(t *testing.T) {
	for _, name := range []string{"auth_chain_a", "auth_chain_f", "auth_aes128_md5", "auth_aes128_sha1"} {
		core.GetApp().SetObfsProtocolService(NewObfsAuthChainData(name))
		p := newChainSide(t, name, map[string]string{}, "")

		for n := 0; n < 8; n++ {
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("%s 对 %d 字节的 UDP 载荷 panic: %v", name, n, r)
					}
				}()
				data, _, err := p.ServerUDPPostDecrypt(make([]byte, n))
				if err != nil {
					t.Fatalf("%s 对 %d 字节的 UDP 载荷回了错误: %s", name, n, err.Error())
				}
				if len(data) != 0 {
					t.Fatalf("%s 对 %d 字节的 UDP 载荷解出了 %d 字节", name, n, len(data))
				}
			}()
		}
	}
}
