# 节点运维

目录：[看日志](#看日志) · [版本与来源](#版本与来源) · [监听地址与多 IP / 双栈](#监听地址与多-ip--双栈) · [手工对账](#手工对账) · [症状与先查什么](#症状与先查什么) · [本机 DNS 缓存](#本机-dns-缓存) · [转发收口的日志摘要](#转发收口的日志摘要)

节点侧的命令与日志与本后端一一对应；面板侧的字段名、日志串和命令按它自己的实现对应过去。

## 看日志

```bash
systemctl status vnet            # sysv 上是 service vnet status
journalctl -u vnet -f
```

启动成功的那一行是 `get node info success`，前面带 id、port、method、protocol、obfs、pushPort 等字段。下面这些行任一条出现，都要按配置或算法名单去查：

| 日志 | 含义 |
| --- | --- |
| `api_host is empty, cannot reach the panel` | 配置没填 `api_host`，或没走命令行标志 |
| `api_host must start with http:// or https://` | 填成了 `panel.example.com` 这种不带协议的串 |
| `node secret is empty, refusing to accept push requests` | 面板没给这个节点配 `secret`，节点不接受推送 |
| `single port mode needs a protocol that carries the account identity` | 单端口配了不携带账号身份的协议，日志里会列出可用协议名 |
| `<method> is a block cipher and cannot carry UDP datagrams` | 分组模式（如 `aes-128-cbc`）配了 UDP，节点拒绝落地 |
| `unsupported protocol or obfs: <name>` | 算法名不在 [capabilities.json](capabilities.json) 里，连接建立不了但心跳照常 |
| `connection handle crashed` | 单条连接的处理协程 panic 后被恢复，端口还在听 |

## 版本与来源

```bash
/usr/bin/vnet/vnet --version          # 第二个字段是当前装着的版本
bash release/upgrade.sh --check       # 只查有没有新版，不改机器
```

版本对账取的是节点二进制 `--version` 的输出与 [release/version.json](../release/version.json) 的 `latest`，两者相同就是最新。判断这台机器上装的是本 fork：`--version` 输出版本号、日志有 `get node info success`、`push_port` 那个端口能连通，三条缺一条就重装一次。

换 key、换基址或修坏安装要用 `-f` 重装：版本相同时不带 `-f` 就装不动，也不会重写 `/etc/vnet/config.json`。开关写给 bash（`bash -s -- -f`），写给 curl 会被它吃掉。日常换版本用 upgrade 那条，它不碰配置、服务单元与调优，新版起不来自动回滚。

## 监听地址与多 IP / 双栈

`release/config.json` 不带 `host` 键，所以部署出来的节点是仅 IPv4 的通配监听（`0.0.0.0`），一台机器上的所有 IPv4 地址共用同一批端口。归属跟客户端从哪个地址进来无关（判据在 [integration.md](integration.md#字段之外的约定)），所以同机多 IP 不造成归属问题——面板逐地址推送、探活只是把同一个进程问 N 遍。

想要双栈，在 `/etc/vnet/config.json` 手写 `"host": "[::]"`。Linux 上 Go 默认双栈，IPv4 连接以 v4 映射地址进来，但上报给面板的在线 IP 取自 `net.IP.String()`，结果仍是点分十进制，面板看到的还是 IPv4 字面量。只有 IPv6 地址的节点怎么处理，见 [integration.md 的寻址一节](integration.md#寻址与鉴权)。

一台机器上挂两行节点且用户端口重叠时，端口→uid 只命中第一个，两个人的流量会记到同一个人头上。

## 手工对账

在面板所在机器上跑（`jq` 在那边）。集合一致性只能拿面板给节点用的同一个端点当基准，另写一份 SQL 就会漂移。

```bash
NODE_ID=7
PANEL=https://panel.example.com      # 面板给节点用的基址，与节点配置里的 api_host 同一个值
KEY=<面板发的节点授权 key>
SECRET=<面板下发的节点 secret>
NODE_HOST=<node.server 或 node.ip 之一>
PUSH_PORT=<node.push_port>

# 面板认为该在线的集合
curl -s -H "key: $KEY" -H "timestamp: $(date +%s)" \
     "$PANEL/api/ssr/v1/userList/$NODE_ID" | jq '[.data[].uid]'

# 节点实际的集合
curl -s -H "secret: $SECRET" "http://$NODE_HOST:$PUSH_PORT/api/user/list" | jq '[.[].uid]'

# 单位抽查：speed_limit 必须是整数字节/秒，出现小数即错
curl -s -H "key: $KEY" -H "timestamp: $(date +%s)" \
     "$PANEL/api/ssr/v1/userList/$NODE_ID" | jq '[.data[].speed_limit] | unique | .[0:5]'

# ETag 命中验证：本后端只对 userList 发 If-None-Match，第二次应为 304
ET=$(curl -sD- -o /dev/null -H "key: $KEY" -H "timestamp: $(date +%s)" \
     "$PANEL/api/ssr/v1/userList/$NODE_ID" | tr -d '\r' | awk -F': ' 'tolower($1)=="etag"{print $2}')
curl -s -o /dev/null -w '%{http_code}\n' -H "key: $KEY" -H "timestamp: $(date +%s)" \
     -H "If-None-Match: $ET" "$PANEL/api/ssr/v1/userList/$NODE_ID"

# 面板侧若有手动对账或重载入口，此时触发一次（重载会断全部在线连接，低峰做）
```

## 症状与先查什么

| 症状 | 先查 |
| --- | --- |
| 节点在线但用户全连不上 | 算法名是否在 [capabilities.json](capabilities.json) 内（存量数据可能带非法名）；日志 `unsupported protocol or obfs`、`connection handle crashed` |
| 进程反复重启，日志没有 `get node info success` | 上面「看日志」那张表；再核对面板侧存的节点 key 与本机配置是不是同一个值 |
| 面板显示在线、心跳正常，但一个人都连不上 | 上报是否被按时差拒掉（两侧时钟差要小于 300 秒）；面板侧的节点 key 是否被换过；算法名是否在名单内 |
| 已禁用或到期的人还在节点上 | 上面两条集合对比；面板侧推删除的那个任务是否失败或积压；节点自己最迟 5 分钟收敛一次 |
| 日志里成批出现 `apply user` | 每行带动作（`add`/`edit`/`remove`）与 `source:`：`push` 是面板推的账号写入，`poll` 是节点每 5 分钟的收敛，`boot`/`reload` 是全量落地。内容没变的账号不记行，所以成批出现就是这一轮真的动了这么多个账号；整批没人变动时只留一行 `apply users no change, source: …, total: …` |
| 流量比实际少 | 上报是否有发送失败的 error 日志（失败的那批留在队列，不会丢）；端口查不到账号的字节被丢弃，即多端口模式下有端口没配用户 |
| 低流量账号的账迟迟不涨 | 正常的：单行不足 50 KiB 会留在节点累加，最长滞留 10 分钟后强制上报（判据见 [integration.md](integration.md#上报的重复窗口)） |
| 在线人数为 0 但有人在用 | 面板是否把这批在线整批拒了（看面板侧的节点 API 日志）；节点是否只有 IPv6 地址 |
| 限速形同不存在或过小 | 下发的是 Mbps 还是字节/秒；`speed_limit` 是否带小数 |
| 推送完全没效果 | 面板给这个节点算出的推送地址是否为空（域名与 ip 都没填）；`push_port` 是否被防火墙挡；`secret` 是否为空 |
| 新建连慢，日志有 `lookup <域名>: i/o timeout` | 在节点上跑 `time getent hosts github.com`，接近 5 秒或 10 秒说明出站 UDP/53 在丢包，见下一节 |

## 本机 DNS 缓存

节点每建立一条转发都要拨一次目标地址（[common/network/conn.go](../common/network/conn.go) 里的 `net.DialTimeout`），域名解析由系统 resolver 完成，进程内没有缓存，所以解析质量直接决定首字节延迟。出站 UDP/53 丢包时，glibc 默认的 `timeout:5 attempts:2` 会让一次查询吃满约 10 秒。

部署脚本的 `--with-dns-cache`（等价 `WITH_DNS_CACHE=1`）装 dnsmasq 做本机缓存。默认关闭：面板给的命令是复制粘贴执行的，改整机解析不该是「装个节点」的隐含副作用。

开启后脚本保证三件事，任何一条不满足就停服务并还原 `/etc/resolv.conf`：

- 只监听回环（`listen-address=127.0.0.1` + `bind-interfaces`）。对外开 53 会让这台机被当成 DNS 放大反射源。
- `/etc/resolv.conf` 里 `nameserver 127.0.0.1` 之后保留原上游作后备，并写 `options timeout:1 attempts:2`，把最坏等待压到 2~4 秒。没有后备那一行，dnsmasq 一挂就是整机无解析。
- 起服务后用 `ss -lntu 'sport = :53'` 断言实际监听地址：必须看到 `127.0.0.1:53`，且不得出现任何非回环地址。`resolv.conf` 是软链（systemd-resolved 接管）时直接跳过，那要改的是 `/etc/systemd/resolved.conf.d/` 的 `DNS=` 与 `Cache=yes`。

缓存救不了不可用的上游：换成本机缓存后单次解析仍超过 5 秒时，脚本还原 `resolv.conf` 并退出，此时该修的是上游解析（换厂商内置 resolver，或走 DoT/DoH）。从安装到断言之间可能有数秒发行版默认配置已生效，事后复查一次 `ss -lntu 'sport = :53'`。

## 转发收口的日志摘要

一条 TCP 连接结束会在 `netx.DuplexCopyTcp` 的两个方向各收口一次；一个方向先结束时会把两侧 deadline 设到过去叫醒另一个方向，所以 `peer_closed` 是这套唤醒机制的正常产物。两个方向都按 error 逐条打会把真异常淹掉，所以按「方向 × 结束原因」计数、明细降到 debug，`conn_reset`、`short_write`、`other` 这类真异常在该分钟内只留一条 error 样本（带 `requestId` 可定位）。每分钟由 `ReportTask` 打一行摘要：

```
copy ended last minute: active_uids=214 up_eof=1200 down_peer_closed=1180 up_conn_reset=3
```

- `active_uids`：本分钟建立过转发的不同会话身份数。多端口模式下键是端口、单端口模式下是面板 uid，两者都与账号一一对应，所以这个数就是活跃账号数。
- `up_*` 是客户端→上游方向的收口，`down_*` 是上游→客户端。
- 原因取值：`eof`、`unexpected_eof`、`peer_closed`、`conn_reset`、`short_write`、`other`。

```bash
journalctl -u vnet | grep "copy ended"
```

看趋势即可；只有 `conn_reset` 或 `other` 抬头才需要去查网络或对端。
