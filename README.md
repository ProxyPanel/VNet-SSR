# VNet-SSR

## 功能介绍
Vnet是一个网络工具,在某些网络条件受到限速的情况根据算法提高网络服务.

## 编译方式
预安装: [Go语言](https://golang.org/), [Bazel](https://docs.bazel.build/)
```sh
rm -rf ~/go/src/github.com/rc452860
git clone https://github.com/ProxyPanel/VNet-SSR.git ~/go/src/github.com/rc452860/vnet && cd ~/go/src/github.com/rc452860/vnet
GO111MODULE=off go get -v ./...
bazel build --action_env=PATH=$PATH --action_env=SPWD=$PWD --action_env=GOPATH=$(go env GOPATH) --action_env=GOCACHE=$(go env GOCACHE) --spawn_strategy local //release:vnet_linux_amd64_package
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
