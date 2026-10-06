package addrx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// 探测地址返回的不一定是 IP：限流时这些站点回 HTML，非空不能当成拿到了地址；
// 这个值只用于启动后的一行观测日志，误判会让日志出现「对外地址=<html>…」这种噪音。
func TestGetPublicIpAcceptsOnlyAnAddress(t *testing.T) {
	cases := []struct {
		name    string
		code    int
		body    string
		want    string
		wantErr bool
	}{
		{"IPv4", http.StatusOK, "203.0.113.9\n", "203.0.113.9", false},
		{"IPv6", http.StatusOK, "2001:db8::1\r\n", "2001:db8::1", false},
		{"限流页不是地址", http.StatusOK, "<html>rate limited</html>", "", true},
		{"空响应体", http.StatusOK, "", "", true},
		{"非 2xx", http.StatusForbidden, "203.0.113.9", "", true},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(item.code)
				_, _ = w.Write([]byte(item.body))
			}))
			defer server.Close()

			got, err := GetPublicIp(server.URL)
			if item.wantErr {
				if err == nil {
					t.Fatalf("%s 应当判为失败，却拿到了 %q", item.name, got)
				}

				return
			}

			if err != nil || got != item.want {
				t.Fatalf("%s: got %q %v, want %q", item.name, got, err, item.want)
			}
		})
	}
}
