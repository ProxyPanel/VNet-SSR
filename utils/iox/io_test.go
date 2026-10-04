package iox

import (
	"os"
	"testing"
)

func Test_IsFileExist(t *testing.T) {
	if IsFileExist("./iox.go") {
		t.Log("exist")
	} else {
		t.Error("not exist")
	}

	if IsFileExist("./iox_.go") {
		t.Error("exist")
	} else {
		t.Log("not exist")
	}
}

func Benchmark_OpenFile(t *testing.B) {
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		file, _ := os.OpenFile("aaa.txt", os.O_APPEND|os.O_CREATE, 0666)
		file.Close()
	}

}

func Benchmark_IsFileExist(t *testing.B) {
	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		IsFileExist("./iox.go")
	}
}
