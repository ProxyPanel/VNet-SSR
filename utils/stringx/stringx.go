package stringx

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strconv"
	"strings"
)

// IsDigit judement data is any of 1234567890
func IsDigit(data string) bool {
	if len(data) != 1 {
		return false
	}
	if strings.IndexAny(data, "1234567890") != -1 {
		return true
	}
	return false
}

func U2S(form string) (to string, err error) {
	bs, err := hex.DecodeString(strings.Replace(form, `\u`, ``, -1))
	if err != nil {
		return
	}
	for i, bl, br, r := 0, len(bs), bytes.NewReader(bs), uint16(0); i < bl; i += 2 {
		binary.Read(br, binary.BigEndian, &r)
		to += string(rune(r))
	}
	return
}

func MustU2S(from string) string {
	result, err := U2S(from)
	if err != nil {
		return ""
	}
	return result
}

func MustUnquote(s string) string {
	r, err := strconv.Unquote(s)
	if err != nil {
		return ""
	}
	return r
}

// Convert string like \u4f60\u597d to utf-8 encode
// \u4f60\u597d means 你好(hello)
func UnicodeToUtf8(s string) string {
	return BUnicodeToUtf8([]byte(s))
}

// BUnicodeToUtf8 解 \uXXXX 转义；转义不完整或十六进制非法时原样保留，不 panic —— 它跑在面板响应文本上
func BUnicodeToUtf8(s []byte) string {
	stringBuffer := new(bytes.Buffer)
	for i := 0; i < len(s); {
		if s[i] == 92 && i+6 <= len(s) && (s[i+1] == 85 || s[i+1] == 117) {
			if temp, err := strconv.ParseInt(string(s[i+2:i+6]), 16, 32); err == nil {
				stringBuffer.WriteRune(rune(temp))
				i += 6
				continue
			}
		}
		stringBuffer.WriteByte(s[i])
		i++
	}
	return stringBuffer.String()
}
