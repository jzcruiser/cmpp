package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
)

type CMPP struct {
	CMPPConf
	conn    net.Conn
	buf     []byte
	offset  uint32
	actived int32
	aid     uint32
}

type HSQS struct {
	HSQSConf
}

type semAccess struct {
	sync.Mutex
	size int
	ids  map[uint32]string
}

type SMRqst struct {
	Id    uint32   `json:"id"`
	Sims  []string `json:"sims"`
	Msg   string   `json:"msg"`
	Valid int64    `json:"valid"`
	At    int64    `json:"at"`
}

type SMResp struct {
	Id    uint32 `json:"id"`
	Sim   string `json:"sim"`
	MsgId uint64 `json:"msgid"`
	Stat  uint32 `json:"stat"`
	Msg   string `json:"msg"`
}

var (
	// program configs
	conf Config
	// run state channel
	broken chan struct{}
	// work channel
	astopped     chan struct{}
	writestopped chan struct{}
	readstopped  chan struct{}
	// request bufs
	req     chan []byte
	reqover int

	sqs  HSQS
	cmpp CMPP

	sem semAccess
	// wg
	wg  sync.WaitGroup
	wg2 sync.WaitGroup
)

func init() {
	conf = Config{}
	conf.InitConfig("conf.yaml")
	// cmpp
	cmpp = CMPP{
		CMPPConf: conf.CMPP,
		buf:      make([]byte, conf.CMPP.BufSz, conf.CMPP.BufSz),
		offset:   0,
		actived:  0,
		aid:      0,
	}
	// sqs
	sqs = HSQS{conf.HSQS}
	// access semphore
	sem = semAccess{sync.Mutex{}, conf.CMPP.SlitSz, make(map[uint32]string)}

}

func worker() {
	broken = make(chan struct{})

	astopped = make(chan struct{})
	writestopped = make(chan struct{})
	readstopped = make(chan struct{})

	req = make(chan []byte, conf.CLIENT.SendBufSz)
	reqover = conf.CLIENT.ReqOverTimes

	for {
		ok, err := cmpp.login()
		if ok {
			logrus.Info("login successed.")
			break
		}
		logrus.WithFields(logrus.Fields{
			"err": err,
		}).Error("login failed, try again after 1 sec.")
		time.Sleep(time.Second * 1)
	}

	go cmpp.readMsg()
	go cmpp.activer()
	go cmpp.writeMsg()

	atomic.StoreInt32(&paused, 0)
	// when getter stopped, wait for all gorutines that write to req stopped.
	sqs.getter()
	wg.Wait()
	fmt.Println("wg exited.")
	<-astopped
	fmt.Println("active exited.")
	close(req)
	<-writestopped
	fmt.Println("writer exited.")
	cmpp.conn.SetReadDeadline(time.Now())
	<-readstopped
	fmt.Println("reader exited.")

	canceled = make(chan struct{})
	atomic.StoreInt32(&cmpp.actived, 0)
	close(wstopped)
}

func (sqs *HSQS) getter() {
	tm := time.NewTimer(time.Second * 1)
	if !tm.Stop() {
		<-tm.C
	}
	log := logrus.WithFields(logrus.Fields{
		"url":  sqs.GetUrl,
		"func": "sqs.getter",
	})
BREAK:
	for {
		resp, err := http.Get(sqs.GetUrl)
		if err != nil {
			log.WithFields(logrus.Fields{
				"err": err,
			}).Error("sqs request failed.")
			continue
		}
		data, _ := ioutil.ReadAll(resp.Body)
		if string(data) != "HTTPSQS_GET_END" {
			wg.Add(1)
			go cmpp.submitMsg(data)
		}

		tm.Reset(time.Second * 1)
		select {
		case <-canceled:
			log.Warn("worker was canceled.")
			break BREAK
		case <-tm.C:
		}
	}

	close(broken)
}

func (sem *semAccess) tryAccess(id uint32, sims string) bool {
	defer sem.Unlock()
	sem.Lock()
	if len(sem.ids) >= sem.size {
		return false
	}

	sem.ids[id] = sims

	return true
}

func (sem *semAccess) isDone(id uint32) bool {
	defer sem.Unlock()
	sem.Lock()
	if _, ok := sem.ids[id]; ok {
		return false
	}

	return true
}

func (sem *semAccess) tryRelease(id uint32) (bool, string) {
	defer sem.Unlock()
	sem.Lock()

	if _, ok := sem.ids[id]; ok {
		sims := sem.ids[id]
		delete(sem.ids, id)
		return true, sims
	}

	return false, ""
}

func (sqs *HSQS) push(content string) {
	log := logrus.WithFields(logrus.Fields{
		// "url":     sqs.HSQSConf.PutUrl,
		"content": content,
		"func":    "sqs.push",
	})
	req, err := http.NewRequest("POST", sqs.PutUrl, bytes.NewBuffer([]byte(content)))
	if err != nil {
		log.WithFields(logrus.Fields{
			"err": err,
		}).Error("request sqs put failed.")
		return
	}
	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		log.WithFields(logrus.Fields{
			"err": err,
		}).Error("request sqs put failed.")
		return
	}
	defer resp.Body.Close()
	respmsg, _ := ioutil.ReadAll(resp.Body)
	if string(respmsg) != "HTTPSQS_PUT_OK" {
		log.WithFields(logrus.Fields{
			"respmsg": respmsg,
		}).Warn("send to sqs failed.")
	}
}
