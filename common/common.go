package common

// TrafficReport 与 OnlineReport 的入参都是端口，不是面板 uid：多端口模式下装饰器的 UID 就是端口，
// 单端口模式下 auth 包的 4 字节装的也是端口（AddUser 用端口生成密码表的键）。
// 实现方内部再按端口反查账号，所以形参不要写成 uid。
type TrafficReport interface {
	Upload(port int, n int64)
	Download(port int, n int64)
}

type OnlineReport interface {
	Online(port int, ip string)
}
