package stringx

import (
	"fmt"
	"testing"
)

func Test_isDigits(t *testing.T) {
	type args struct {
		data string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			"test",
			args{
				data: "1",
			},
			true,
		},
		{
			"test",
			args{
				data: "2",
			},
			true,
		},
		{
			"test",
			args{
				data: "22",
			},
			false,
		},
		{
			"test",
			args{
				data: "a",
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDigit(tt.args.data); got != tt.want {
				t.Errorf("isDigits() = %v, want %v", got, tt.want)
			}
		})
	}
}


func ExampleUnicodeToUtf8() {
	test := "aaa\\u6388\\u6743\\u9a8c\\u8bc1\\u5931\\u8d25\\uff1a\\u8bf7\\u6c42\\u53d7\\u9650"
	fmt.Println(UnicodeToUtf8(test))
	//Output:
	//aaa授权验证失败：请求受限
}

// 面板不回 JSON_UNESCAPED_UNICODE，中文以 \uXXXX 到达，必须解回可读文本
func TestUnicodeToUtf8DecodesEscapes(t *testing.T) {
	in := "{\"message\":\"\\u6388\\u6743\\u5931\\u8d25\"}"
	want := `{"message":"授权失败"}`
	if got := UnicodeToUtf8(in); got != want {
		t.Errorf("UnicodeToUtf8() = %q, want %q", got, want)
	}
	if got := BUnicodeToUtf8([]byte(in)); got != want {
		t.Errorf("BUnicodeToUtf8() = %q, want %q", got, want)
	}
}

// 反斜杠后面不是完整 \uXXXX 时原样保留：这段文本来自面板响应，
// 在这里 panic 会让 main 的启动路径直接崩，systemd 把它拖进重启循环
func TestUnicodeToUtf8KeepsIncompleteEscape(t *testing.T) {
	for _, in := range []string{`C:\\users`, `abc\`, `\u4f`, `x\uzzzz`, `tail\u`, `\`, ``} {
		if got := UnicodeToUtf8(in); got != in {
			t.Errorf("UnicodeToUtf8(%q) = %q, want 原样保留", in, got)
		}
		if got := BUnicodeToUtf8([]byte(in)); got != in {
			t.Errorf("BUnicodeToUtf8(%q) = %q, want 原样保留", in, got)
		}
	}
}