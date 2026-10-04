package obfs

import (
	"encoding/hex"
	"fmt"
)

func ExampleNewHttpSimple() {
	plain, _ := NewHttpSimple("http_simple")
	h := plain.(*HttpSimple)
	data := h.encodeHead([]byte("helloa"))
	fmt.Print(hex.EncodeToString(data))
	//Output:
	//253638253635253663253663253666253631
}
