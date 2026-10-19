# 开发本仓

目录：[环境与构建](#环境与构建) · [目标平台](#目标平台) · [测试](#测试) · [CI](#ci) · [发版](#发版) · [算法名单](#算法名单) · [写代码时要守的几条](#写代码时要守的几条)

## 环境与构建

需要 Go 1.26 及以上（`go.mod` 的 go 指令由依赖树的最低要求决定）。拉不到 proxy.golang.org 时命令前加 `GOPROXY=https://goproxy.cn,direct`。

```bash
go build -o vnet ./cmd/shadowsocksr-server   # 只编当前平台
go vet ./...
go test ./...
make                                         # 全平台交叉编译，产物落 bin/
make package                                 # 打成 deploy.sh 认的 zip，落 dist/
```

`make package` 的产物形状由 [release/package.sh](../release/package.sh) 头部注释定义：资产名 `vnet-linux-<VDIS>.zip`，解压后目录里必须有 `vnet`、`config.json`、`systemd/vnet.service`——deploy.sh 按这三项落地。

## 目标平台

`CGO_ENABLED=0` 交叉编译：darwin/amd64、freebsd/386、freebsd/amd64、linux/386、linux/amd64、linux/arm、linux/arm64、linux/mips、linux/mipsle、linux/mips64、linux/mips64le、windows/386、windows/amd64。mips 系用 `GOMIPS=softfloat`。

## 测试

`go test ./...` 全部离线：不连面板也不连外网，仓库不保留需要真实面板地址的活体样例。

- 面板侧用 `httptest` 起假面板，跑真实请求构造：鉴权头、ETag 与 304、上报批次里的 `report_id`、空列表与「取不到集合」的区分。
- 节点侧用同样方式打 push 路由：`secret` 判据、重载失败时保留原配置。
- 协议与混淆走内存内回环；监听与每连接 framing 用真端口真 socket——被拒绝的连接要确认 socket 关掉了，审计命中要注入 403 或 302，UDP 要整包取出。
- `common/capabilities` 有一条测试拿现场注册表与 `docs/capabilities.json` 比对。
- `core/version_test.go` 钉住 `APP_VERSION` 与 `release/version.json` 的 `latest` 相同。

`go test -race` 在这台开发机上跑不了（要 cgo），由 CI 的 race job 兜。

## CI

[.github/workflows/build.yml](../.github/workflows/build.yml) 的闸门：

| 步骤 | 为什么要有 |
| --- | --- |
| `bash -n release/*.sh` | 脚本经 raw.githubusercontent 直接下发，语法错是最便宜的闸门 |
| `go mod verify`、`go vet`、`go test` | 基本正确性 |
| 独立的 `go test -race` | 用户表锁、`atomic.Value` 存取 ETag 与 push secret、32 位目标上的 int64 计数器都需要 race 检测才兜得住 |
| 全平台 `make` | 交叉编译面 |
| tag 触发的 `make package` + `gh release create` | 发全平台包 |
| `govulncheck` | `continue-on-error: true`，只报告不阻断 |

## 发版

版本号只有一个来源：[release/version.json](../release/version.json) 的 `latest`。`core.APP_VERSION` 必须等于它（`core/version_test.go` 钉住），tag 名也必须等于它。

发版动作 = 改 `version.json` + 改 `APP_VERSION` + 打同名 tag。CI 只在 tag 上发布，`make package` 的默认 `VERSION` 取自 `version.json`，CI 用 tag 覆盖。deploy.sh 与 upgrade.sh 每次拉 master，装哪个版本随那份 json 走，所以脚本里不写版本号。

## 算法名单

名单的唯一来源是代码里的注册表，文件是生成的：

```bash
go run ./cmd/capabilities > docs/capabilities.json
```

改了算法实现就重生成，否则 `go test ./...` 里那条比对会失败。

面板侧要按这份 json 存一份白名单，在保存节点时挡住名单外的算法名：本后端对名单外的名字不报错下线，而是拒绝建立连接、心跳照常上报，面板看起来「在线、无人」。同步流程就三步——本仓动实现、重生成 `capabilities.json`、把三组名单交给面板侧。

某个算法要不要接进来，看两件事：有没有已知漏洞，有没有可信的 Go 实现。

## 写代码时要守的几条

- 不做 `InsecureSkipVerify`：跳过证书校验等于任何中间人都能冒充面板，下发用户表与节点配置。
- 32 位平台（linux/386、arm、mips）上 `atomic` 读写的 int64 计数器要放结构体最前面，见 [common/network/decorate.go:71](../common/network/decorate.go#L71)。
- 面板的 HTTP 状态分不开永久失败与暂时失败，判据只取响应体业务码；把暂时失败当成永久会丢账，反过来会让一条毒丸钉死整条重投队列。
- 快照清账发生在发送之前：发送失败的整批要原样留在待发队列，不能与新数据合并——合并会让 `report_id` 对不上内容，面板的去重就废了。
- 单端口只要求协议携带账号身份；分组密码不承载 UDP 数据报。两种组合都在落地之前拒掉，见 `api/server` 的 `ValidateNodeInfo`。
