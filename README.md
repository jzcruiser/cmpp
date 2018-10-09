# 移动物联网短消息客户端
客户端使用go编写，实现了sp与移动网关之间的通信，采用长链接方式，支持短消息群发。
## 运行环境
centos7、 fedora22
## 依赖
* [httpsqs](http://zyan.cc/httpsqs/)  
设计上使用httpsqs实现与客户端交互，客户端从httpsqs轮询待发消息，收到消息后将其发送给移动网关。在收到网关消息后将消息推送给httpsqs。用户在使用客户端时
只需要访问httpsqs即可。当然也可以提供webapi站点作为客户端的请求与推送地址，只需要将这些地址配置到配置文件conf.yaml中。
## 消息格式
用户可以通过想httpsqs 推送消息来发送消息，通过从httpsqs消息拉取消息还回去消息应答。消息请求与应答均采用json格式。
* 消息请求  
``` json
    {
      "id": 1,
      "sims": ["1064848122018", "1064848122017"],
      "msg": "hello world!",
      "valid": 0,
      "at": 0
    }
```  
valid为短消息有效日期， at为发送时间，两者格式均为utc时间戳  
* 消息应答
``` json
    {
      "id": 1,
      "sim": "1064848122018",
      "msgid": "1234556678",
      "stat": 1,
      "msg": "消息已下发"
    }
```  
stat 取值有  
  * 1:  消息已下发  
  * 2:  消息已下达  
  * 3:  设备应答，此时msg内容为对端响应内容。
  * 4:  发送失败，此时msg内容为失败原因。  
  
 ## 测试  
 模拟cmpp服务端 [easy](https://github.com/svnwell/easy.git)
 
 ## 联系我
 `QQ`   : 786558585@qq.com  
 `WCHAT`: x_dotor  
 `EMAIL`: x_dotor@163.com
