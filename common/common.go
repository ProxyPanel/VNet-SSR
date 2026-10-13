package common

// TrafficReport 与 OnlineReport 的入参都是线上身份编号，两种模式下都是端口：
// 多端口下是监听端口，单端口下是 auth 包头 4 字节里的账号编号（面板建号时保证全局唯一）。
// 实现方内部按它反查账号，形参不要写成 uid。
type TrafficReport interface {
	Upload(identity int, n int64)
	Download(identity int, n int64)
}

type OnlineReport interface {
	Online(identity int, ip string)
}
