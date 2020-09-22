package osx

import (
	"os"
	"os/signal"
	"syscall"
)

func WaitSignal()os.Signal{
	signalChan := make(chan os.Signal,1)
	signal.Notify(signalChan,syscall.SIGINT, syscall.SIGTERM,syscall.SIGQUIT,syscall.SIGKILL,syscall.SIGHUP)
	if sig,ok := <- signalChan;ok{
		return sig
	}
	return nil
}
