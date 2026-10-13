package stream

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// testdata/blockmodes.golden 由 pycryptodome 按 NIST SP800-38A 的逐字节反馈定义生成，
// 生成时 cfb8/ofb 对过 NIST 官方向量、cfb1 的比特打包对过 openssl enc -aes-128-cfb1。
type modeVector struct {
	Name       string `json:"name"`
	Key        string `json:"key"`
	IV         string `json:"iv"`
	Plaintext  string `json:"plaintext"`
	Ciphertext string `json:"ciphertext"`
}

func TestBlockModesMatchGoldenVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/blockmodes.golden")
	if err != nil {
		t.Fatalf("读取黄金向量失败：%s", err.Error())
	}

	var doc struct {
		Vectors []modeVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("黄金向量解析失败：%s", err.Error())
	}
	if len(doc.Vectors) != 9 {
		t.Fatalf("应为 3 密钥长度 × 3 模式共 9 组，实得 %d", len(doc.Vectors))
	}

	for _, v := range doc.Vectors {
		// 向量名 aes-cfb8-128 换成注册名 aes-128-cfb8
		parts := strings.Split(v.Name, "-")
		if len(parts) != 3 || parts[0] != "aes" {
			t.Fatalf("向量名解析失败：%s", v.Name)
		}
		name := "aes-" + parts[2] + "-" + parts[1]
		cipherImpl := GetStreamCipher(name)
		if cipherImpl == nil {
			t.Fatalf("%s 未注册", name)
		}
		key, _ := hex.DecodeString(v.Key)
		iv, _ := hex.DecodeString(v.IV)
		pt, _ := hex.DecodeString(v.Plaintext)
		want, _ := hex.DecodeString(v.Ciphertext)

		enc, err := cipherImpl.NewStream(key, iv, 0)
		if err != nil {
			t.Fatalf("%s 建流失败：%s", name, err.Error())
		}
		got := make([]byte, len(pt))
		enc.XORKeyStream(got, pt)
		if hex.EncodeToString(got) != hex.EncodeToString(want) {
			t.Errorf("%s 加密与黄金向量不符", name)
		}

		// 解密方向的反馈取自输入：CFB 补入密文比特/字节，OFB 与方向无关
		dec, err := cipherImpl.NewStream(key, iv, 1)
		if err != nil {
			t.Fatalf("%s 建解密流失败：%s", name, err.Error())
		}
		back := make([]byte, len(want))
		dec.XORKeyStream(back, want)
		if hex.EncodeToString(back) != hex.EncodeToString(pt) {
			t.Errorf("%s 解密回环不符", name)
		}
	}
}

func TestRC4MD56UsesSixByteIV(t *testing.T) {
	c := GetStreamCipher("rc4-md5-6")
	if c == nil {
		t.Fatal("rc4-md5-6 未注册")
	}
	if c.IVLen() != 6 || c.KeyLen() != 16 {
		t.Fatalf("rc4-md5-6 应为 key=16 iv=6，实得 key=%d iv=%d", c.KeyLen(), c.IVLen())
	}
}
