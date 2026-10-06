# 与面板的对接方式

字段级契约见 [`openapi.yaml`](openapi.yaml)，支持的算法名单见 [`capabilities.json`](capabilities.json)。
本文只讲契约之外的东西：寻址、同步通道、幂等判据、对账操作，以及名单怎么同步。

## 1. 寻址与鉴权

* **节点 → 面板**：基址 = 配置里的 `api_host`（部署脚本用环境变量 `WEB_API` 写入 `/etc/vnet/config.json`），
  路径前缀 `/api/ssr/v1`。每个请求带 `key` 与 `timestamp`（unix 秒）；面板要求两侧时差 <300 秒。
  `api_host` 为空时进程直接报错退出，不会带着空基址启动。
* **面板 → 节点**：`http://{地址}:{push_port}`，每个请求带 `secret` 头。地址由面板的
  `Node::pushAddresses()` 决定：DDNS 节点用域名，否则用 `node.ip` 逗号拆出的多 IP，两者都没填时退回域名。
* 面板的 `web/v1`、`vnet/v2` 前缀由其它后端使用，本后端只用 `ssr/v1`；三条前缀在面板侧指向同一份实现。

## 2. 监听地址与「多 IP / 双栈」

监听地址取配置的 `host`，默认 `0.0.0.0`，且 `release/config.json` 里没有 `host` 键 →
部署出来的节点是 **仅 IPv4 的通配监听**，一台机器上的所有 IPv4 地址共用同一批端口。

* 因此「同机多 IP」不会造成归属问题：流量按**本地监听端口 → uid** 反查（单端口模式按鉴权包里的 uid），
  与客户端从哪个地址进来无关。面板逐地址推送/轮询只是把同一个进程问 N 遍。
* 想要双栈需在 `/etc/vnet/config.json` 手写 `"host": "[::]"`（Linux 上 Go 默认双栈，IPv4 会以
  `::ffff:a.b.c.d` 的映射地址进来，在线上报里会带这层前缀）。注意面板侧目前**只按 IPv4 寻址**：
  推送、对账、探活都取自 `ips()`（IPv4 列表），`node.ipv6` 只用于列表徽标。v6-only 的节点会显示离线且收不到推送。
* 一个风险留给配置层：两行节点指向同一台机器且用户端口重叠时，端口→uid 只能命中第一个，
  两个人的流量会记到同一个人头上。

## 3. 三条同步通道

| 通道 | 触发 | 频率 | 作用 |
| --- | --- | --- | --- |
| 全量拉取 | 节点启动、`api/v2/node/reload` | 事件驱动 | 用户集合 + 节点配置 + 审计规则 |
| 增量推送 | 面板的 `UserObserver` / `NodeObserver` | 即时 | 账号增删改、节点配置变更 |
| 双向对账 | 面板 `vnet:reconcile`；节点周期同步 | 面板每 10 分钟；节点每 5 分钟 | 只增删用户，不 reload，所以不断在线连接 |

推送是加速器，一致性由对账兜住：推送丢一次（节点重启、队列积压、网络抖动）会让已禁用或到期的账号
长期留在节点上，最长 5 分钟后被收敛。

## 4. 幂等与失败判据

* `api/v2/user/add/list` **按 uid 落目标状态**：`enable=0` 摘号，内容一致不动，有差异才重建。
  重复推同一批不会多出一份，因此面板可以安全重投（传输层未送达 → 队列重投；节点明确回绝 → 只记日志）。
* `api/v2/node/reload` 会断掉全部在线连接，面板不自动重投；本后端**先拉用户列表再改配置**，
  拉不到就保留当前服务并回错误，不会把已经在跑的端口打空。
* 上报侧：流量与在线快照在发送前清账，所以发送失败必须并回待上报表 —— 那一分钟的字节在面板只有一份记录。
* 「拉不到集合」与「集合为空」必须区分：`GET /api/user/list` 的 `[]` 是「节点上没人」，
  鉴权失败/非 2xx/传输异常是另一回事。把前者当后者会让整节点用户被当成缺漏重推。
* 审计规则里 `type = protocol` 本后端不实现（静默忽略）；`client_limit` 只在
  `auth_aes128_md5`/`auth_aes128_sha1`/`auth_chain_a` 下生效。

## 5. 算法名单怎么维护（面板侧镜像的来源）

名单的唯一来源是代码里的注册表，文件是生成的：

```bash
go run ./cmd/capabilities > docs/capabilities.json
```

`common/capabilities` 有一条测试拿现场注册表与该文件比对：改了实现却没重生成，`go test ./...` 就失败。
面板（OtakuCloud）在 `app/Utils/VNet/Supported.php` 里存了一份镜像常量，用于在后台保存 VNET 节点时挡住
名单外的算法名 —— 本后端对名单外的名字不会报错下线，而是**拒绝建立连接、心跳照常上报**，
面板看起来「在线、无人」，用户侧全断。

**同步流程**：本仓改动算法实现 → 重生成 `capabilities.json` → 把三组名单抄进面板的 `Supported`
（SSR 那套后端名单不同，不受它约束）。

## 6. 手工对账

```bash
NODE_ID=7
PANEL=https://panel.example.com      # 必须等于面板的 web_api_url ?: website_url
KEY=<node_auth.key>
SECRET=<node_auth.secret>
NODE_HOST=<node.server 或 node.ip 之一>
PUSH_PORT=<node.push_port>

# 面板认为该在线的集合（走面板给节点用的同一个端点，不要另写 SQL 造第二个判据）
curl -s -H "key: $KEY" -H "timestamp: $(date +%s)" \
     "$PANEL/api/ssr/v1/userList/$NODE_ID" | jq '[.data[].uid]'

# 节点实际集合
curl -s -H "secret: $SECRET" "http://$NODE_HOST:$PUSH_PORT/api/user/list" | jq '[.[].uid]'

# 单位抽查：speed_limit 必须是整数字节/秒，出现小数即错
curl -s -H "key: $KEY" -H "timestamp: $(date +%s)" \
     "$PANEL/api/ssr/v1/userList/$NODE_ID" | jq '[.data[].speed_limit] | unique | .[0:5]'

# ETag 命中验证（第二次应为 304）
ET=$(curl -sD- -o /dev/null -H "key: $KEY" -H "timestamp: $(date +%s)" \
     "$PANEL/api/ssr/v1/node/$NODE_ID" | tr -d '\r' | awk -F': ' 'tolower($1)=="etag"{print $2}')
curl -s -o /dev/null -w '%{http_code}\n' -H "key: $KEY" -H "timestamp: $(date +%s)" \
     -H "If-None-Match: $ET" "$PANEL/api/ssr/v1/node/$NODE_ID"

# 手工触发对账 / 重载（重载会断在线连接，低峰做）
php artisan vnet:reconcile --node=$NODE_ID
php artisan vnet:reload
```

### 症状 → 先查什么

| 症状 | 先查 |
| --- | --- |
| 节点在线但用户全连不上 | 算法名是否在 `capabilities.json` 内（存量数据可能带非法名）；节点日志 `unsupported protocol or obfs` / `connection handle crashed` |
| 进程反复重启、日志有 `no Host in request URL` | 装的是 2020 年的上游包（Release 只有 v2.1.0）；确认 `journalctl -u vnet` 里有没有 `get node info success` |
| 已禁用/到期的人还在节点上 | 上面两条集合对比；面板日志 `【删除用户】未送达` |
| 流量比实际少 | 上报窗口是否有发送失败（旧包整轮丢弃）；`< 50KiB` 起报门槛 |
| 在线人数为 0 但有人在用 | `nodeOnline` 是否被整批拒收（`【在线上报】…已跳过`） |
| 限速形同不存在或过小 | 下发的是 Mbps 还是字节/秒；`speed_limit` 是否为小数 |
| 推送完全没效果 | 面板 `pushAddresses()` 是否为空（非 DDNS 且 `ip` 没填）；`push_port` 是否被防火墙挡 |
