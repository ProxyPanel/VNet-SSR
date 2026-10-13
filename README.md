# VNet-SSR

OtakuCloud 账号面板的 SSR 协议节点后端，Go 单进程。它不发放账号也不计费：启动时按 `node_id` + `key`
向面板拉本节点的监听配置与用户表，按端口起转发，再周期性回传流量、在线、心跳与审计命中；面板反向推送账号增删、
节点重载与审计规则重拉。没有可达的面板，进程在拉配置那一步就退出。

上游是 2020 年的 VNet 2.1.0（GPL-3.0）；算法、转发收口、会话身份与接口契约都已重写。变更与理由见 git log
与 [GitHub Releases](https://github.com/ProxyPanel/VNet-SSR/releases)。面板对 ShadowsocksR 与 VNET 两种节点类型
下发的是本仓同一套部署命令。

## 部署（Linux，一条命令）

面板后台节点授权页的部署命令弹窗里复制的那一行就是完整可用的，凭据已经在里面：

```bash
curl -L -s https://raw.githubusercontent.com/ProxyPanel/VNet-SSR/master/release/deploy.sh \
| WEB_API="https://panel.example.com" NODE_ID=7 NODE_KEY=<node_auth.key> WITH_TUNE=1 bash
```

装完落地三样东西：

| 位置 | 内容 |
| --- | --- |
| `/usr/bin/vnet/vnet` | 二进制，同时在 `/usr/local/bin/vnet` 建软链 |
| `/etc/vnet/config.json` | 配置，见下面「配置」一节 |
| `vnet` | 服务单元，systemd 与 sysv 自动择一（`systemctl status vnet`） |

`WITH_TUNE=1` 让装机顺带跑 `release/tune.sh`：只写 `/etc/sysctl.d`、`/etc/modules-load.d`、`/etc/modprobe.d` 与
vnet 的 systemd drop-in 四处，不动 sshd、不动防火墙、不加 `-r` 就不重启 vnet，`--rollback` 一键删掉这些改动。
`WITH_DNS_CACHE=1` 装 dnsmasq 本机解析缓存，默认不开 —— 判据与回退写在 `docs/api.md` 第 7 节。
其余开关看 `bash release/deploy.sh -h`：`--check` 只查有没有新版，`-f` 版本相同也重装（换 key/基址要用它），
`--version vX.Y.Z` 装指定版本，`--remove` 卸载，`-l FILE` 从本地包装，`-p URL` 走代理下载。

## 日常升级（只换二进制）

```bash
curl -L -s https://raw.githubusercontent.com/ProxyPanel/VNet-SSR/master/release/upgrade.sh | bash
```

不碰 `/etc/vnet/config.json`、不碰服务单元、不碰系统调优、不需要凭据；下载后先验版本再装，
新版起不来自动回滚旧版。`--check` 只查不改，`--version vX.Y.Z` 就是退回旧版的通道。
多节点滚动方式写在脚本头部注释里。

升级**不需要**删除或重生成配置：配置的四个键与版本无关，同版本重装也不会重写它们。

## 配置

`/etc/vnet/config.json` 只有四个键，改完 `systemctl restart vnet`：

| 键 | 含义 |
| --- | --- |
| `api_host` | 面板基址，不含路径，例 `https://panel.example.com`；必须等于面板的 `web_api_url ?: website_url` |
| `node_id` | 面板上的节点 id，填 0 视为未填 |
| `key` | 节点授权 key（面板 `node_auth.key`） |
| `host` | 监听地址，默认 `0.0.0.0`（仅 IPv4 通配；双栈行为见 `docs/api.md` 第 2 节） |

四个键也能用同名命令行标志传（`vnet --api_host … --node_id 7 --key …`），`--config` 默认读当前目录的 `config.json`。
`api_host` 为空或鉴权不过时进程直接退出，不会带着坏配置跑。

面板下发、不在本文件里的两项是 `push_port` 与 `secret`：`secret` 为空时节点拒绝启动 push 服务、也拒绝重载，
否则不带 `secret` 头的请求会与空期望值相等，等于把「改用户表、重载整节点」开放给任何能连上该端口的人。

## 支持的算法

名单以机器可读的 [`docs/capabilities.json`](docs/capabilities.json) 为准：30 种加密 / 10 种协议 / 6 种混淆。
本文不抄名单（抄了就会过期）。唯一来源是代码里的注册表，文件是生成的：

```bash
go run ./cmd/capabilities > docs/capabilities.json
```

`common/capabilities` 有测试拿现场注册表与该文件比对，改了实现却没重生成就会失败。

面板在 `app/Utils/VNet/Supported.php` 存了一份镜像常量，用于保存节点时挡住名单外的算法名。这个白名单是必要的：
本后端对名单外的名字不报错下线，而是拒绝建立连接、心跳照常上报，面板看起来「在线、无人」。
同步流程、以及刻意不接的上游算法清单（因漏洞移除的与无可信 Go 实现的）见 `docs/api.md` 第 5 节。

## 开发与构建

预装 Go 1.26 及以上（go.mod 的 go 指令由依赖树的最低要求决定）。拉不到 proxy.golang.org 时命令前加
`GOPROXY=https://goproxy.cn,direct`。

```bash
go build -o vnet ./cmd/shadowsocksr-server   # 只编当前平台
go test ./...                                # 31 个包有测试，全部离线（httptest 与内存内回环，不连面板也不连外网）
go vet ./...
make                                         # 全平台交叉编译，产物落 bin/
make package                                 # 打成部署脚本认的 zip，落 dist/
```

目标平台：darwin/amd64、freebsd/386、freebsd/amd64、linux/386、linux/amd64、linux/arm、linux/arm64、
linux/mips、linux/mipsle、linux/mips64、linux/mips64le（mips 系用 `GOMIPS=softfloat`）、windows/386、
windows/amd64。

测试都在默认跑法里，仓库不保留 `//go:build manual` 那种需要真实面板地址的活体样例：面板侧用 httptest 假面板
跑真实请求构造（鉴权头、ETag 与 304、上报批次里的 `report_id`、空列表与取不到集合的区分），节点侧用同样的方式
打 push 路由（secret 判据与重载失败时保留原配置），协议与混淆走内存内回环，监听与每连接 framing 用真端口和
真 socket（拒绝的连接要关掉 socket、审计命中要注入 403 或 302、UDP 要整包取出）。

**版本号只有一个来源：`release/version.json` 的 `latest`。** `core.APP_VERSION`（即 `vnet --version` 输出的第二个
字段，两个脚本都取它做版本对账）与 tag 名都必须等于它，`core/version_test.go` 钉住这条；`make package` 的默认
`VERSION` 也从这里取，CI 用 tag 覆盖。发版 = 改 `version.json` + 改 `APP_VERSION` + 打同名 tag，CI 只在 tag 上发布。

CI（`.github/workflows/build.yml`）依次跑 `bash -n release/*.sh`（脚本经 raw.githubusercontent 直接下发，语法错是最便宜的闸门）、
`go mod verify`、`go vet`、`go test`，然后并行一个 `go test -race` 的 job（用户表锁、`atomic.Value` 存取 ETag 与 push secret、
32 位目标上必须落在结构体首地址的 int64 计数器，这些判据都需要 race 检测才兜得住；开发机没有 C 编译器，这条只能在 CI 上验）、
以及全平台 `make`；tag 触发 `make package` 并发 GitHub Release；govulncheck 只报告不阻断。

## 目录

| 路径 | 内容 |
| --- | --- |
| `core` | 进程级单例：配置、节点信息、跨模块接口 |
| `service` | 端口与用户表管理、限速、审计规则、上报任务 |
| `proxy/server` | 单个 SSR 监听的建立与转发 |
| `api/client` | 调面板：拉节点配置/用户列表/审计规则，上报流量/在线/状态/命中 |
| `api/server` | 面板反向推送的 HTTP 服务：用户增删、node reload、rule reload |
| `common/ciphers` | 流密码、分组模式（cfb/cfb8/cfb1/ofb/cbc/ctr）、AEAD |
| `common/obfs` | 协议（`auth_*`）与混淆（`http_simple`/`http_post`/`tls1.2_ticket_*`） |
| `common/network` | 连接装饰器、监听器、转发请求 |
| `common/{cache,pool,capabilities,log}` | LRU 缓存、字节池、算法名单、日志 |
| `model` | 与面板交换的数据结构；字段级契约的唯一来源是 `docs/openapi.yaml` |
| `utils` | `addrx`/`netx`/`iox`/`sniff`/`socksproxy`/`stringx` 等不带领域的小工具 |
| `release` | `deploy.sh`/`upgrade.sh`/`tune.sh`/`package.sh`/`version.json`/`config.json`/systemd 与 sysv 单元 |
| `cmd` | `shadowsocksr-server` 入口；`capabilities` 名单生成器 |

## 文档

- [`docs/api.md`](docs/api.md) —— 对接方式：寻址与鉴权、监听与多 IP/双栈、三条同步通道、幂等与失败判据、
  算法名单怎么同步、手工对账命令、症状→先查什么、本机 DNS 缓存、转发收口的日志形态
- [`docs/openapi.yaml`](docs/openapi.yaml) —— 双向接口契约（面板侧 7 个端点、节点侧 8 个）
- [`docs/capabilities.json`](docs/capabilities.json) —— 算法名单，生成物，不要手改
- 面板侧对应实现：OtakuCloud 的 `app/Http/Controllers/Api/WebApi`、`app/Jobs/VNet/*`、`app/Utils/VNet/Supported.php`

## 许可

GPL-3.0（全文见 [`LICENSE`](LICENSE)），版权 © 2017-2020 ProxyPanel 及本仓贡献者。
