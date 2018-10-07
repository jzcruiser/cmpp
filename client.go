package main

import (
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
)

var (
	exit   int32 = 0
	paused int32 = 0
	// program cancel stat
	canceled chan struct{}
	// program was interupted or abnormaled.
	interupt chan os.Signal
	abnormal chan struct{}
	// worker state channel
	wstopped chan struct{}

	listen chan struct{}
	bye    chan struct{}
)

func init() {
	interupt = make(chan os.Signal)
	signal.Notify(interupt, syscall.SIGINT, syscall.SIGTERM)
	canceled = make(chan struct{})
	abnormal = make(chan struct{})
	listen = make(chan struct{})
	bye = make(chan struct{})
}

func main() {
	go listenToAbort()
	for {
		wstopped = make(chan struct{})
		go worker()
		<-wstopped
		if atomic.LoadInt32(&exit) == 1 {
			termBytes, err := cmpp.encodeTerminate()
			if err == nil {
				cmpp.conn.Write(*termBytes)
			}
			close(bye)
			<-listen
			break
		}
		cmpp.conn.Close()
	}
}

func listenToAbort() {
EXIT:
	for {
		select {
		case <-interupt:
			atomic.StoreInt32(&exit, 1)
		case <-abnormal:
		case <-bye:
			break EXIT
		}
		if atomic.CompareAndSwapInt32(&paused, 0, 1) {
			close(canceled)
		}
	}
	close(listen)
}
