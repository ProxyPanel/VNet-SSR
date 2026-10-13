package randomx

import (
	"bytes"
	"testing"
)

// RandomBytes 喂的是 IV、ClientID 与 ticket：长度错了会让线格式错位，全零等于没有随机量
func TestRandomBytesLengthAndEntropy(t *testing.T) {
	for _, size := range []int{1, 4, 16, 18, 32} {
		got := RandomBytes(size)
		if len(got) != size {
			t.Fatalf("RandomBytes(%d) 返回 %d 字节", size, len(got))
		}
		if bytes.Equal(got, make([]byte, size)) {
			t.Fatalf("RandomBytes(%d) 全零，crypto/rand 没读到东西", size)
		}
	}

	first, second := RandomBytes(16), RandomBytes(16)
	if bytes.Equal(first, second) {
		t.Fatal("两次 RandomBytes(16) 相同，IV 会重复")
	}
}

// RandIntRange 是闭区间（Intn((max+1)-min)+min），补全长度与包长抖动都按它取值；
// 两端都要真的取到，否则 Intn(max-min) 这种半开写法也能过关
func TestRandIntRangeIsInclusive(t *testing.T) {
	distinct := make(map[int]bool)
	for i := 0; i < 1000; i++ {
		v := RandIntRange(3, 6)
		if v < 3 || v > 6 {
			t.Fatalf("RandIntRange(3,6) 给出 %d", v)
		}
		distinct[v] = true
	}
	if !distinct[3] || !distinct[6] {
		t.Fatalf("1000 次没同时取到两端 3 与 6，实际取值集合 %v", distinct)
	}

	if got := RandIntRange(5, 5); got != 5 {
		t.Fatalf("min==max 时应回 min, got %d", got)
	}
}

func TestRangeHelpersStayInsideBounds(t *testing.T) {
	for i := 0; i < 1000; i++ {
		if v := Float64Range(0, 8); v < 0 || v >= 8 {
			t.Fatalf("Float64Range(0,8) 给出 %v，obfs_tls 的 1/8 概率判据会失真", v)
		}
	}

	seen := make(map[uint16]bool)
	for i := 0; i < 200; i++ {
		v := Uint16()
		seen[v] = true
	}
	if len(seen) < 2 {
		t.Fatal("Uint16 一直返回同一个值")
	}
}

// 主机名与补长列表都是「从给定的几个里挑」，挑出列表外的值会让 SNI 与 ticket 对不上
func TestChoiceHelpersPickFromTheGivenList(t *testing.T) {
	hosts := []string{"a.example.com", "b.example.com"}
	for i := 0; i < 200; i++ {
		got := RandomStringsChoice(hosts)
		if got != hosts[0] && got != hosts[1] {
			t.Fatalf("RandomStringsChoice 给出列表外的 %q", got)
		}
	}

	sizes := []int{32, 40}
	for i := 0; i < 200; i++ {
		got := RandomIntChoice(sizes)
		if got != 32 && got != 40 {
			t.Fatalf("RandomIntChoice 给出列表外的 %d", got)
		}
	}
}
