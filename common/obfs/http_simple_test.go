package obfs

import (
	"encoding/hex"
	"fmt"
)

func ExampleClientEncode(){
	h := NewHttpSimple("http_simple").(*HttpSimple)
	data := h.encodeHead([]byte("helloa"))
	fmt.Printf(hex.EncodeToString(data))
	//Output:
	//253638253635253663253663253666
}
