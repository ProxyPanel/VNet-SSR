# VNet-SSR

## 功能介绍
Vnet是一个网络工具,在某些网络条件受到限速的情况根据算法提高网络服务.

## 开发计划
- [ x ] shadowsocsk代理协议
- [  ] kcp自定义协议
- [ x ] 代理服务流量统计
- [ x ] 代理服务速度监控
- [  ] restful api(进行中)
- [ x ] 服务器cpu 内存 硬盘 上传下载速度监控

## 已知问题
- [ ] log formatter setdepth 多线程问题待改进



## 运行
linux去release页面下载对应的指令集二进制文件给运行权限直接运行,根据提示输入对应的配置好

window直接运行exe

linx:
```
wget https://github.com/rc452860/vnet/releases/download/v0.0.4/vnet_linux_amd64 -O vnet && chmod +x vnet && ./vnet
#配置好数据库后按ctrl + c退出使用nohup启动
nohup ./vnet>vnet.log 2>&1 &
```

重新启动
```
kill -9 $(ps aux | grep '[v]net' | awk '{print $2}') && nohup ./vnet>vnet.log 2>&1 &
```



## 编译方式
```
go get -u -d github.com/rc452860/vnet/...
```

进入$gopath/rc452860/vnet目录

```
go build cmd/server/server.go
```

windows 上使用`build.cmd`脚本可以快速编译linux和windows

## 直接使用方式(无需编译)
在release页面下载最新的对应的可执行文件并赋予可执行权限
列如64位linux系统
```
wget https://github.com/rc452860/vnet/releases/download/v0.0.4/vnet_linux_amd64 -O vnet &&chmod +x vnet
./vnet
```
按照提示输入数据库等配置信息即可完成

后台运行使用`nohup`工具辅助
```
nohup ./vnet >vnet.log 2>&1 &
```

## 支持加密方式
```
aes-256-cfb
bf-cfb
chacha20
chacha20-ietf
aes-128-cfb
aes-192-cfb
aes-128-ctr
aes-192-ctr
aes-256-ctr
cast5-cfb
des-cfb
rc4-md5
salsa20
aes-256-gcm
aes-192-gcm
aes-128-gcm
chacha20-ietf-poly1305
```

## 注意事项
config.json配置文件中的所有时间单位都为毫秒
升级后续删除原有config.json重新生成
