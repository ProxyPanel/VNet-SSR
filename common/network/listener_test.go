package network

import (
	"context"
	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/utils/osx"
	"strings"
	"time"
)

func ExampleTest(){
	ctx,cancel := context.WithCancel(context.Background())

	tmpFunc := func (){
		select {
			case <- ctx.Done():
				println("done")
		}
	}
	go tmpFunc()
	go tmpFunc()

	tick := time.After(3*time.Second)
	println("start ...")
	<-tick
	cancel()
	//Output:
}

func ExampleTest2(){
	done := make(chan struct{})

	tmpFunc := func(){
		select{
		case <- done:
			println("done")
		}
	}
	go tmpFunc()
	go tmpFunc()

	println("start...")
	tick := time.After(3*time.Second)
	<-tick
	close(done)
	//Output:
}

func ExampleListener(){
	listener := NewListener("127.0.0.1:1000",5*time.Second)
	listener.ListenUDP(func(request *Request){
		for{
			buf := make([]byte,2048)
			_,_,err := request.ReadFrom(buf)
			if err != nil{
				if strings.Contains(err.Error(), " use of closed network connection"){
					println(err.Error())
					return
				}
				log.Err(err)
			}
			log.Info(string(buf))
		}
	})
	listener.ListenTCP(func(request *Request){
		buf := make([]byte,2048)
		for{
			n,err:=request.Read(buf)
			if err != nil{
				log.Err(err)
			}
			log.Info(string(buf[:n]))
		}
	})
	osx.WaitSignal()
	println("close listener")
	listener.Close()
	osx.WaitSignal()
	//Output:
}