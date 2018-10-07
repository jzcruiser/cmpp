package main

import (
	"io/ioutil"

	yaml "gopkg.in/yaml.v2"
)

type HSQSConf struct {
	GetUrl string `yaml:"GetUrl"`
	PutUrl string `yaml:"PutUrl"`
	Cycle  int    `yaml:"Cycle"`
}

type CMPPConf struct {
	GateAddr     string `yaml:"GateAddr"`
	GatePort     int    `yaml:"GatePort"`
	UserName     string `yaml:"UserName"`
	Password     string `yaml:"Password"`
	ServiceId    string `yaml:"ServiceId"`
	PlatformCode string `yaml:"PlatformCode"`
	SlitSz       int    `yaml:"SlitSz"`
	BufSz        int    `yaml:"BufSz"`
}

type ClientConf struct {
	SendBufSz    int `yaml:"SendBufSz"`
	ReqOverTimes int `yaml:"ReqOverTimes"`
	RecvBufSz    int `yaml:"RecvBufSz"`
	RspOverTimes int `yaml:"RspOverTimes"`
}

type Config struct {
	HSQS   HSQSConf   `yaml:"HSQS"`
	CMPP   CMPPConf   `yaml:"CMPP"`
	CLIENT ClientConf `yaml:"CLIENT"`
}

func (conf *Config) InitConfig(fileName string) {

	f, err := ioutil.ReadFile(fileName)
	if err != nil {
		panic(err)
	}

	err = yaml.Unmarshal(f, conf)
	if err != nil {
		panic(err)
	}
}
