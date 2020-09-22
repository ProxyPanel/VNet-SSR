package randomx

import "fmt"

func ExampleRandom(){
	for i := 0;i<1000;i++{
		fmt.Println(RandIntRange(0,1024))
	}
	// Output:
}
