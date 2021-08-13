package main

import "github.com/ProxyPanel/VNet-SSR/utils/osx"

func main(){
	println("start...")
	println(osx.WaitSignal().String())
}
