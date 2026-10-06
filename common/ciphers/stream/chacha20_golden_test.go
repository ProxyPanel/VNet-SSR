package stream

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// testdata/chacha20.golden 是换源前用原实现（gitlab.com/yawning/chacha20）跑出的 keystream，
// 按 1/3/32/63/64/65/128/1000 字节的分块续读生成。它同时钉住两件事：
// 8 字节 IV 提升成 RFC 8439 nonce 的等价性，以及跨块续读时计数器的推进。
type chachaVector struct {
	Name      string `json:"name"`
	Key       string `json:"key"`
	IV        string `json:"iv"`
	Chunks    []int  `json:"chunks"`
	Keystream string `json:"keystream"`
}

func TestChaCha20MatchesTheGoldenKeystream(t *testing.T) {
	raw, err := os.ReadFile("testdata/chacha20.golden")
	if err != nil {
		t.Fatalf("读取黄金向量失败：%s", err.Error())
	}

	var doc struct {
		Vectors []chachaVector `json:"vectors"`
	}

	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("黄金向量解析失败：%s", err.Error())
	}

	if len(doc.Vectors) != 2 {
		t.Fatalf("黄金向量应为 8 字节 IV 与 12 字节 IV 两组，实得 %d", len(doc.Vectors))
	}

	for _, vector := range doc.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			name := "chacha20"
			if strings.Contains(vector.Name, "ietf") {
				name = "chacha20-ietf"
			}

			cipher := GetStreamCipher(name)
			if cipher == nil {
				t.Fatalf("%s 未注册", name)
			}

			key, err := hex.DecodeString(vector.Key)
			if err != nil {
				t.Fatalf("key 解析失败：%s", err.Error())
			}

			iv, err := hex.DecodeString(vector.IV)
			if err != nil {
				t.Fatalf("iv 解析失败：%s", err.Error())
			}

			if len(iv) != cipher.IVLen() {
				t.Fatalf("注册表给的 IV 长度与实际用例不符：%d != %d", len(iv), cipher.IVLen())
			}

			stream, err := cipher.NewStream(key, iv, 0)
			if err != nil {
				t.Fatalf("建流失败：%s", err.Error())
			}

			buf := make([]byte, len(vector.Keystream)/2)
			offset := 0

			for _, chunk := range vector.Chunks {
				stream.XORKeyStream(buf[offset:offset+chunk], make([]byte, chunk))
				offset += chunk
			}

			if got := hex.EncodeToString(buf); got != vector.Keystream {
				t.Fatalf("keystream 与换源前不一致，首个差异在第 %d 字节", firstDiff(got, vector.Keystream))
			}
		})
	}
}

// firstDiff 以「两个 hex 串」为输入，返回首个不一致的字节序号（hex 每 2 字符一个字节）
func firstDiff(got, want string) int {
	for i := 0; i+1 < len(got) && i+1 < len(want); i += 2 {
		if got[i:i+2] != want[i:i+2] {
			return i / 2
		}
	}

	return -1
}
