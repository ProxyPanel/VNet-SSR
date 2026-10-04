# VNet-SSR

## 功能介绍
Vnet是一个网络工具,在某些网络条件受到限速的情况根据算法提高网络服务.

## 编译方式
预安装: [Go语言](https://golang.org/) 1.26 及以上（go.mod 里的 go 指令由依赖树的最低要求决定）

只编译当前平台：
```sh
go build -o vnet ./cmd/shadowsocksr-server
```

拉不到 proxy.golang.org 时用模块镜像：
```sh
GOPROXY=https://goproxy.cn,direct go build -o vnet ./cmd/shadowsocksr-server
```

交叉编译全部目标平台，产物落在 bin/：
```sh
make
make clean
```

目标平台：darwin/amd64、freebsd/386、freebsd/amd64、linux/386、linux/amd64、linux/arm、linux/arm64、linux/mips、linux/mipsle、linux/mips64、linux/mips64le（mips 系用 GOMIPS=softfloat）、windows/386、windows/amd64。

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
