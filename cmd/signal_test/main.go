package main

import "github.com/rc452860/vnet/utils/osx"

func main(){
	println("start...")
	println(osx.WaitSignal().String())
}
