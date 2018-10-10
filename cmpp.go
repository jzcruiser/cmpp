package main

import (
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

const (
	cmdConnect       uint32 = 0x00000001
	cmdConnectResp   uint32 = 0x80000001
	cmdTerminate     uint32 = 0x00000002
	cmdTerminateResp uint32 = 0x80000002
	cmdSubmit        uint32 = 0x00000004
	cmdSubmitResp    uint32 = 0x80000004
	cmdDeliver       uint32 = 0x00000005
	cmdDeliverResp   uint32 = 0x80000005
	cmdQuery         uint32 = 0x00000006
	cmdQueryResp     uint32 = 0x80000006
	cmdCancel        uint32 = 0x00000007
	cmdCancelResp    uint32 = 0x80000007
	cmdActive        uint32 = 0x00000008
	cmdActiveResp    uint32 = 0x80000008
	fmtASCII         byte   = 0
	fmtSMWrite       byte   = 3
	fmtBinary        byte   = 4
	fmtUCS2          byte   = 8
	fmtGBK           byte   = 16
)

var deliverd [7]byte = [7]byte{'D', 'E', 'L', 'I', 'V', 'R', 'D'}

func isdelivrd(stat [7]byte) bool {
	for i := 0; i < 7; i++ {
		if stat[i] != deliverd[i] {
			return false
		}
	}
	return true
}

type HeaderT struct {
	TotalLen uint32
	CmdId    uint32
	SeqId    uint32
}

type ConnectT struct {
	HeaderT
	SrcAddr    [6]byte
	AuthSource [16]byte
	Version    uint8
	Timestamp  uint32
}

type ConnectRespT struct {
	HeaderT
	Status   uint32
	AuthISMG [16]byte
	Version  byte
}

type LoginRst struct {
	Code    uint32
	Version byte
}

func (rst *LoginRst) String() string {
	msg := "success"
	switch rst.Code {
	case 0:
		msg = "success"
		break
	case 1:
		msg = "invalid msg structure"
		break
	case 2:
		msg = "invalid source addr"
		break
	case 3:
		msg = "authentication failed"
		break
	case 4:
		msg = "version higher"
		break
	default:
		msg = "other errors"
		break
	}
	return fmt.Sprintf("code: %d version:%d.%d msg:%s",
		rst.Code, (rst.Version>>4)&0x0f, rst.Version&0x0f, msg)
}

type TerminateT struct {
	HeaderT
}

type TerminateRespT struct {
	HeaderT
}

type SubmitT struct {
	HeaderT
	MsgId           uint64
	PkTotal         byte
	PkNumber        byte
	RegiDelivery    byte
	MsgLevel        byte
	ServiceId       [10]byte
	FeeUserType     byte
	FeeTerminalId   [32]byte
	FeeTerminalType byte
	TpPId           byte
	TpUDHI          byte
	MsgFmt          byte
	MsgSrc          [6]byte
	FeeType         [2]byte
	FeeCode         [6]byte
	ValidTime       [17]byte
	AtTime          [17]byte
	SrcId           [21]byte
	DestUsrTl       byte
	// destTermId      []byte
	// destTermType    byte
	// msgLen          byte
	// msgConent       []byte
}

type SubmitRespT struct {
	HeaderT
	MsgId  uint64
	Result uint32
}

type QueryT struct {
	HeaderT
	Time      [8]byte
	QueryType byte
	QueryCode [10]byte
	Reserve   [8]byte
}

type QueryRespT struct {
	HeaderT
	Time      [8]byte
	QueryType byte
	QueryCode [10]byte
	MtTlMsg   uint32
	MtTlUser  uint32
	MtScc     uint32
	MtWt      uint32
	MtFl      uint32
	MoScc     uint32
	MoWt      uint32
	MoFl      uint32
}

type DeliverT struct {
	HeaderT
	MsgId        uint64
	DestId       [21]byte
	ServiceId    [10]byte
	Tppid        byte
	Tpudhi       byte
	MsgFmt       byte
	SrcTermId    [32]byte
	SrcTermType  byte
	RegiDelivery byte
	MsgLen       byte
	// msgContent []byte
}

type DeliverStatusT struct {
	MsgId      uint64
	Stat       [7]byte
	SubTime    [10]byte
	DoneTime   [10]byte
	DestTermId [21]byte
	SmscSeq    uint32
}

type DeliverRespT struct {
	HeaderT
	MsgId  uint64
	Result uint32
}

type CancelT struct {
	HeaderT
	MsgId uint64
}

type CancelRespT struct {
	HeaderT
	SuccessId uint32
}

type ActiveTestT struct {
	HeaderT
}

type ActiveTestRespT struct {
	HeaderT
	Reserved byte
}

func (cmpp *CMPP) subpackage(recvBytes *[]byte) *[][]byte {
	var rst [][]byte

	copy(cmpp.buf[cmpp.offset:], *recvBytes)
	cmpp.offset += uint32(len(*recvBytes))
	// skip this package when offset is illeagel
	if cmpp.offset > uint32(cap(cmpp.buf)) {
		cmpp.offset = 0
		return &rst
	}

	var cursor uint32 = 0
	for cursor+4 <= cmpp.offset {
		bytesLen := binary.BigEndian.Uint32(cmpp.buf[cursor : cursor+4])
		// skip bad package
		if bytesLen == 0 {
			cmpp.offset = 0
			return &rst
		}
		if cursor+bytesLen > cmpp.offset {
			break
		}
		rsti := make([]byte, bytesLen, 1024)
		copy(rsti, cmpp.buf[cursor:cursor+bytesLen])
		rst = append(rst, rsti)
		cursor += bytesLen
	}
	copy(cmpp.buf[0:], cmpp.buf[cursor:cmpp.offset])
	cmpp.offset -= cursor

	return &rst
}

func (cmpp *CMPP) encodeLogin() (*[]byte, error) {
	buf := bytes.Buffer{}

	// connection package
	connect := ConnectT{
		HeaderT: HeaderT{
			TotalLen: 39,
			CmdId:    cmdConnect,
			SeqId:    0,
		},
		Version: 0x30,
	}
	copy(connect.SrcAddr[:], []byte(cmpp.UserName)[:len(cmpp.UserName)])
	// get auth source
	tm := time.Now().Local()
	authrc := make([]byte, 100)
	copy(authrc, connect.SrcAddr[:])
	copy(authrc[6:], []byte{0, 0, 0, 0, 0, 0, 0, 0, 0})
	copy(authrc[15:], []byte(cmpp.Password)[:len(cmpp.Password)])
	copy(authrc[15+len(cmpp.Password):], []byte(tm.Format("0102150405"))[:10])
	connect.AuthSource = md5.Sum(authrc[:25+len(cmpp.Password)])
	// get timestamp
	ts, _ := strconv.Atoi(tm.Format("0102150405"))
	connect.Timestamp = uint32(ts)

	err := binary.Write(&buf, binary.BigEndian, connect)
	if err != nil {
		return nil, err
	}

	rst := buf.Bytes()
	return &rst, nil
}

func (cmpp *CMPP) decodeLogin(bts *[]byte) (*LoginRst, error) {
	rst := LoginRst{}

	crt := ConnectRespT{}

	buf := bytes.NewBuffer(*bts)
	err := binary.Read(buf, binary.BigEndian, &crt)
	if err != nil {
		return nil, err
	}

	rst.Code = crt.Status
	rst.Version = crt.Version

	return &rst, nil
}

func (cmpp *CMPP) login() (bool, error) {
	log := logrus.WithFields(logrus.Fields{
		"func": "login",
		"dest": fmt.Sprintf("%s:%d\n", cmpp.GateAddr, cmpp.GatePort),
	})
	cmpp.offset = 0
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", cmpp.GateAddr, cmpp.GatePort), time.Second*1)
	if err != nil {
		return false, err
	}
	logbytes, err := cmpp.encodeLogin()
	if err != nil {
		return false, err
	}
	log.WithFields(logrus.Fields{
		"bytes": fmt.Sprintf("%x", *logbytes),
	}).Info("send login bytes.")
	conn.Write(*logbytes)
	for {
		rcvbytes := make([]byte, 1024)
		rdcount, err := conn.Read(rcvbytes)
		if err != nil {
			return false, err
		}
		loginBytes := rcvbytes[0:rdcount]
		subBytes := cmpp.subpackage(&loginBytes)
		for _, rspBytes := range *subBytes {
			switch binary.BigEndian.Uint32(rspBytes[4:8]) {
			case cmdConnectResp:
				logrst, err := cmpp.decodeLogin(&rspBytes)
				if err != nil {
					return false, err
				}
				if logrst.Code == 0 {
					cmpp.conn = conn
					return true, nil
				}
				err = errors.New(logrst.String())
				return false, err
			case cmdSubmitResp:
				log.WithFields(logrus.Fields{
					"bytes": rspBytes,
				}).Warn("recvd submit resp package.")
			case cmdDeliver:
				log.WithFields(logrus.Fields{
					"bytes": rspBytes,
				}).Warn("recvd deliver package.")
			case cmdActiveResp:
				log.WithFields(logrus.Fields{
					"bytes": rspBytes,
				}).Warn("recvd active resp package.")
			case cmdActive:
				log.WithFields(logrus.Fields{
					"bytes": rspBytes,
				}).Warn("recvd active package.")
			}
		}
	}
}

func (cmpp *CMPP) encodeSubmit(id uint32, sims []string, msg string, survive int64, at int64) (*[]byte, error) {
	buf := bytes.Buffer{}

	submit := SubmitT{
		HeaderT: HeaderT{
			CmdId: cmdSubmit,
			SeqId: id,
		},
		MsgId:           0,
		PkTotal:         1,
		PkNumber:        1,
		RegiDelivery:    1,
		MsgLevel:        0,
		FeeUserType:     0,
		FeeTerminalId:   [32]byte{0},
		FeeTerminalType: 0,
		TpPId:           0,
		TpUDHI:          0,
		MsgFmt:          0,
		FeeType:         [2]byte{0x30, 0x31},
		FeeCode:         [6]byte{0},
		ValidTime:       [17]byte{0},
		AtTime:          [17]byte{0},
		DestUsrTl:       byte(len(sims)),
	}
	submit.TotalLen = uint32(163 + len(sims)*32 + len(msg))
	copy(submit.ServiceId[:], []byte(cmpp.ServiceId)[:len(cmpp.ServiceId)])
	copy(submit.MsgSrc[:], []byte(cmpp.UserName)[:len(cmpp.UserName)])
	if survive != 0 {
		tm := time.Unix(survive, 0)
		copy(submit.ValidTime[:], []byte(fmt.Sprintf("%02d%02d%02d%02d%02d%02d%d32+",
			tm.Year()%100, tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), tm.Second()%10)))
	}
	if at != 0 {
		tm := time.Unix(at, 0)
		copy(submit.AtTime[:], []byte(fmt.Sprintf("%02d%02d%02d%02d%02d%02d%d32+",
			tm.Year()%100, tm.Month(), tm.Day(), tm.Hour(), tm.Minute(), tm.Second(), tm.Second()%10)))
	}
	copy(submit.SrcId[:], []byte(cmpp.PlatformCode))

	err := binary.Write(&buf, binary.BigEndian, submit)
	if err != nil {
		return nil, err
	}

	rst := buf.Bytes()

	rest := make([]byte, 32*len(sims)+2+len(msg)+20)
	cursor := len(rst)

	rst = append(rst, rest...)
	for _, sim := range sims {
		copy(rst[cursor:], []byte(sim)[:len(sim)])
		cursor += 32
	}
	rst[cursor] = 0
	cursor++
	rst[cursor] = byte(len(msg))
	cursor++
	copy(rst[cursor:], []byte(msg)[:len(msg)])

	return &rst, nil

}

func (cmpp *CMPP) decodeSubmitResp(recvBytes *[]byte) (*SMResp, error) {
	rst := SMResp{}

	sr := SubmitRespT{}
	buf := bytes.NewBuffer(*recvBytes)
	err := binary.Read(buf, binary.BigEndian, &sr)
	if err != nil {
		return nil, err
	}

	rst.Id = sr.SeqId
	rst.MsgId = sr.MsgId
	if sr.Result == 0 {
		rst.Stat = 1
		rst.Msg = "消息已发送"
	} else {
		rst.Stat = 4
		rst.Msg = fmt.Sprintf("消息下发失败，错误码:%d", sr.Result)
	}

	return &rst, nil
}

func (cmpp *CMPP) submitMsg(content interface{}) {
	defer wg.Done()
	n := 3
	log := logrus.WithFields(logrus.Fields{
		"content": string(content.([]byte)),
		"func":    "cmpp.submitMsg",
	})
	smreq := SMRqst{}
	err := json.Unmarshal(content.([]byte), &smreq)
	if err != nil {
		log.WithFields(logrus.Fields{
			"err": err,
		}).Error("json unmashal SMRqst failed.")
		return
	}
	if !sem.tryAccess(smreq.Id, strings.Join(smreq.Sims, ",")) {
		resp := SMResp{
			Id:    smreq.Id,
			Sim:   strings.Join(smreq.Sims, ","),
			MsgId: 0,
			Msg:   "server is busy, try again later.",
			Stat:  4,
		}
		content, err := json.Marshal(resp)
		if err != nil {
			log.WithFields(logrus.Fields{
				"err":    err,
				"object": resp,
			}).Error("json mashal SMResp failed.")
			return
		}
		sqs.push(string(content))
		return
	}

	for n > 0 {
		n--
		subbytes, err := cmpp.encodeSubmit(smreq.Id, smreq.Sims, smreq.Msg, smreq.Valid, smreq.At)
		if err != nil {
			log.WithFields(logrus.Fields{
				"err": err,
			}).Error("submit encode failed.")
			return
		}
		select {
		case <-broken:
			return
		case req <- *subbytes:
			log.WithFields(logrus.Fields{
				"bytes": fmt.Sprintf("%x", *subbytes),
			}).Info("send msg")
			break
		}
		select {
		case <-broken:
			return
		case <-time.After(time.Second * 60):
			break
		}
		if sem.isDone(smreq.Id) {
			return
		}
	}
	log.Error("submit overtimes, canceld.")
	smrsp := SMResp{
		Id:    smreq.Id,
		Stat:  4,
		MsgId: 0,
		Msg:   "server was not responsed, canceld.",
	}
	if ok, sims := sem.tryRelease(smreq.Id); ok {
		smrsp.Sim = sims
		content, err := json.Marshal(smrsp)
		if err != nil {
			log.WithFields(logrus.Fields{
				"err": err,
			}).Error("json marshal smrsp failed.")
			return
		}
		sqs.push(string(content))
	}
}

func (cmpp *CMPP) encodeActive(id uint32) (*[]byte, error) {
	buf := bytes.Buffer{}
	active := ActiveTestT{
		HeaderT: HeaderT{
			TotalLen: 12,
			CmdId:    cmdActive,
			SeqId:    id,
		},
	}
	err := binary.Write(&buf, binary.BigEndian, active)
	if err != nil {
		return nil, err
	}

	rst := buf.Bytes()

	return &rst, nil
}

func (cmpp *CMPP) encodeActiveResp(id uint32) (*[]byte, error) {
	buf := bytes.Buffer{}
	actresp := ActiveTestRespT{
		HeaderT: HeaderT{
			TotalLen: 13,
			CmdId:    cmdActiveResp,
			SeqId:    id,
		},
		Reserved: 0,
	}

	err := binary.Write(&buf, binary.BigEndian, actresp)

	if err != nil {
		return nil, err
	}

	rst := buf.Bytes()

	return &rst, nil
}

func (cmpp *CMPP) activer() {
	log := logrus.WithFields(logrus.Fields{
		"func": "cmpp.activer",
	})
	tm := time.NewTimer(time.Second * 1)
	if !tm.Stop() {
		<-tm.C
	}
	// max active detect times
	n := 3
EXIT:
	for {
	ACTIVE:
		for n > 0 {
			n--
			actbytes, err := cmpp.encodeActive(cmpp.aid)
			if err != nil {
				log.WithFields(logrus.Fields{
					"err": err,
					"sid": cmpp.aid,
				}).Error("active encoded failed.")
				break
			}
			// if connect was actived, don't send active package
			if atomic.CompareAndSwapInt32(&cmpp.actived, 1, 0) {
				break
			}
			// send active package
			select {
			case <-broken:
				log.WithFields(logrus.Fields{
					"sid": cmpp.aid,
				}).Error("active was canceled.")
				break EXIT
			case req <- *actbytes:
				log.WithFields(logrus.Fields{
					"sid":   cmpp.aid,
					"bytes": fmt.Sprintf("%x", *actbytes),
				}).Info("send active detect.")
			}
			// sleep 60 secs, and check connect state
			tm.Reset(time.Second * 60)
			select {
			case <-tm.C:
				if atomic.CompareAndSwapInt32(&cmpp.actived, 1, 0) {
					break ACTIVE
				}
			case <-broken:
				log.WithFields(logrus.Fields{
					"sid": cmpp.aid,
				}).Error("active was canceled.")
				break EXIT
			}
		}
		if n == 0 {
			// connection was disactived, reconnect!
			log.WithFields(logrus.Fields{
				"sid": cmpp.aid,
			}).Error("active was broken. reboot!")
			abnormal <- struct{}{}
			break EXIT
		}
		n = 3
		cmpp.aid++

		tm.Reset(time.Second * 120)
		select {
		case <-broken:
			log.WithFields(logrus.Fields{
				"sid": cmpp.aid,
			}).Warn("active was canceld.")
			break EXIT
		case <-tm.C:
		}
	}
	close(astopped)
}

func (cmpp *CMPP) decodeDeliver(bts *[]byte) (*SMResp, error) {
	rst := SMResp{}
	deliver := DeliverT{}
	buf := bytes.NewBuffer((*bts)[:89])
	err := binary.Read(buf, binary.BigEndian, &deliver)
	if err != nil {
		return nil, err
	}
	// not delivery state report
	if deliver.RegiDelivery == 0 {
		rst.Id = deliver.SeqId
		rst.Sim = string(bytes.TrimRight(deliver.SrcTermId[:], "\x00"))
		rst.Stat = 3
		rst.MsgId = deliver.MsgId
		msg := (*bts)[89 : 89+deliver.MsgLen]
		switch deliver.MsgFmt {
		case fmtBinary:
			rst.Msg = fmt.Sprintf("%x", msg)
			break
		case fmtUCS2:
			e := unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM)
			es, _, err := transform.Bytes(e.NewDecoder(), msg)
			if err != nil {
				rst.Msg = string(bytes.TrimRight(msg, "\x00"))
				break
			}
			rst.Msg = string(bytes.TrimRight(es, "\x00"))
			break
		case fmtGBK:
			data, err := ioutil.ReadAll(transform.NewReader(bytes.NewReader(msg), simplifiedchinese.GBK.NewEncoder()))
			if err != nil {
				rst.Msg = string(bytes.TrimRight(msg, "\x00"))
			}
			rst.Msg = string(bytes.TrimRight(data, "\x00"))
			break
		default:
			rst.Msg = string(bytes.TrimRight(msg, "\x00"))
		}
		return &rst, nil
	}

	delstat := DeliverStatusT{}
	stabytes := (*bts)[89 : 89+deliver.MsgLen]
	stabuf := bytes.NewBuffer(stabytes)
	err = binary.Read(stabuf, binary.BigEndian, &delstat)
	if err != nil {
		return nil, err
	}
	rst.Sim = string(bytes.TrimRight(delstat.DestTermId[:], "\x00"))
	rst.MsgId = delstat.MsgId
	rst.Stat = 2
	rst.Msg = "消息已下达"
	if !isdelivrd(delstat.Stat) {
		rst.Msg = fmt.Sprintf("消息发送失败，错误码:%s", string(delstat.Stat[:]))
		rst.Stat = 4
	}

	return &rst, nil
}

func (cmpp *CMPP) encodeDeliverResp(id uint32, msgId uint64) (*[]byte, error) {
	buf := bytes.Buffer{}
	delresp := DeliverRespT{
		HeaderT: HeaderT{
			TotalLen: 24,
			CmdId:    cmdDeliverResp,
			SeqId:    id,
		},
		MsgId:  msgId,
		Result: 0,
	}
	err := binary.Write(&buf, binary.BigEndian, delresp)
	if err != nil {
		return nil, err
	}
	rst := buf.Bytes()

	return &rst, nil
}

func (cmpp *CMPP) encodeTerminate() (*[]byte, error) {
	buf := bytes.Buffer{}
	term := TerminateT{
		HeaderT: HeaderT{
			TotalLen: 12,
			CmdId:    cmdTerminate,
			SeqId:    0,
		},
	}
	err := binary.Write(&buf, binary.BigEndian, term)
	if err != nil {
		return nil, err
	}

	rst := buf.Bytes()

	return &rst, nil
}

func (cmpp *CMPP) encodeTerminateResp(id uint32) (*[]byte, error) {
	buf := bytes.Buffer{}

	termresp := TerminateRespT{
		HeaderT: HeaderT{
			TotalLen: 12,
			CmdId:    cmdTerminateResp,
			SeqId:    id,
		},
	}

	err := binary.Write(&buf, binary.BigEndian, termresp)
	if err != nil {
		return nil, err
	}

	rst := buf.Bytes()

	return &rst, nil
}

func (cmpp *CMPP) writeMsg() {
	log := logrus.WithFields(logrus.Fields{
		"func": "writeMsg",
	})
	for wbyte := range req {
		_, err := cmpp.conn.Write(wbyte)
		if err != nil {
			log.WithFields(logrus.Fields{
				"err": err,
			}).Error("socket write error.")
			break
		}
	}
	close(writestopped)
}

func (cmpp *CMPP) readMsg() {
	log := logrus.WithFields(logrus.Fields{
		"func": "cmpp.readMsg",
	})
EXIT:
	for {
		recvBytes := make([]byte, 1024)
		recvCount, err := cmpp.conn.Read(recvBytes)
		if err != nil {
			log.WithFields(logrus.Fields{
				"err": err,
			}).Error("cmpp socket read failed.")
			abnormal <- struct{}{}
			break EXIT
		}
		recvBytes = recvBytes[0:recvCount]
		rdBytes := cmpp.subpackage(&recvBytes)
		for _, rspBytes := range *rdBytes {
			atomic.StoreInt32(&cmpp.actived, 1)
			wg2.Add(1)
			go cmpp.procBytes(rspBytes)
		}
	}
	log.Warn("wait for wg2 closed.")
	wg2.Wait()
	close(readstopped)
}

func (cmpp *CMPP) procBytes(p interface{}) {
	defer wg2.Done()
	rcvBytes := p.([]byte)
	log := logrus.WithFields(logrus.Fields{
		"bytes": fmt.Sprintf("%x", rcvBytes),
		"func":  "cmpp.procBytes",
	})
	switch binary.BigEndian.Uint32(rcvBytes[4:8]) {
	case cmdConnectResp:
		log.Info("recvd login resp.")
		break
	case cmdSubmitResp:
		log.Info("recvd submit resp.")
		smresp, err := cmpp.decodeSubmitResp(&rcvBytes)
		if err != nil {
			log.WithFields(logrus.Fields{
				"err": err,
			}).Error("submit resp decode failed.")
			break
		}
		if ok, sims := sem.tryRelease(smresp.Id); ok {
			smresp.Sim = sims
			content, err := json.Marshal(smresp)
			if err != nil {
				log.WithFields(logrus.Fields{
					"err": err,
				}).Error("json marshal submit resp error.")
				break
			}
			sqs.push(string(content))
		}
		break
	case cmdActive:
		log.Info("recvd active package.")
		actbytes, err := cmpp.encodeActiveResp(binary.BigEndian.Uint32(rcvBytes[8:12]))
		if err != nil {
			log.WithFields(logrus.Fields{
				"err": err,
			}).Error("active resp encode failed.")
			break
		}
		respMsg(actbytes)
		break
	case cmdActiveResp:
		log.Info("recvd active resp")
		break
	case cmdQueryResp:
		log.Info("recvd cancel resp")
		break
	case cmdDeliver:
		log.Info("recvd deliver msg.")
		delRspBytes, err := cmpp.encodeDeliverResp(binary.BigEndian.Uint32(rcvBytes[8:12]), binary.BigEndian.Uint64(rcvBytes[12:20]))
		if err != nil {
			log.WithFields(logrus.Fields{
				"err": err,
			}).Error("encode deliver resp failed.")
		} else {
			respMsg(delRspBytes)
		}
		smrsp, err := cmpp.decodeDeliver(&rcvBytes)
		if err != nil {
			log.WithFields(logrus.Fields{
				"err": err,
			}).Error("decode deliver failed.")
			break
		}
		content, err := json.Marshal(smrsp)
		if err != nil {
			log.WithFields(logrus.Fields{
				"err": err,
			}).Error("json marshal deliver smrsp failed")
			break
		}
		sqs.push(string(content))
		break
	case cmdCancelResp:
		log.Info("recvd cancel resp.")
		break
	case cmdTerminate:
		log.Warn("recvd terminate pack.")
		termbytes, err := cmpp.encodeTerminateResp(binary.BigEndian.Uint32(rcvBytes[8:12]))
		if err != nil {
			log.WithFields(logrus.Fields{
				"err": err,
			}).Error("encode terminate resp failed.")
		} else {
			respMsg(termbytes)
		}
		abnormal <- struct{}{}
		break
	case cmdTerminateResp:
		log.Info("recvd terminal resp.")
	}
}

func respMsg(bts *[]byte) {
	log := logrus.WithFields(logrus.Fields{
		"func": "respMsg",
	})
	select {
	case <-time.After(time.Second * time.Duration(reqover)):
		log.Error("resp overtimed")
	case <-broken:
		log.Error("task was canceld.")
	case req <- *bts:
	}
}
