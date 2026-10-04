//go:build manual

package iox

import (
	"os"
	"testing"
	"time"
)

func Test_OpenFileWrite(t *testing.T) {
	file, err := os.OpenFile("aaa.txt", os.O_APPEND|os.O_CREATE, 0666)
	defer file.Close()
	if err != nil {
		panic(err)
	}
	for i := 0; i < 20; i++ {
		file.WriteString("aaa\n")
		time.Sleep(1 * time.Second)
	}
}
