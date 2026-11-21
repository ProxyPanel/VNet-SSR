# 节点运维

目录：[看日志](#看日志) · [版本与来源](#版本与来源) · [监听地址与多 IP / 双栈](#监听地址与多-ip--双栈) · [手工对账](#手工对账) · [症状与先查什么](#症状与先查什么) · [本机 DNS 缓存](#本机-dns-缓存) · [转发收口的日志摘要](#转发收口的日志摘要) · [系统加固与自动运维](#系统加固与自动运维)

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

## 系统加固与自动运维

`release/harden.sh` 是独立的一步（与 deploy/tune/upgrade 同族），把前置配置与安全加固一次做完。deploy.sh 的边界不动：装机不隐含改整机，加固单独跑。幂等重跑、只写自己生成的配置、`--rollback` 退回、改前改后打印读数。

做的事：

- 开跑前 `dpkg --audit` 预检：有没配完的包就黄字列出（之后每笔 apt 事务都会被它卡住），提示 `dpkg --configure -a` 重试或 purge 掉那个包再重跑——**只提示，不代修包**。
- 时区 `Asia/Shanghai`；vnstat 接口流量统计（与面板按用户记账互为对照：接口总量 vs 用户分量）。
- ddns 续租（ddns.newfuture.cc）：pipx 装 ddns → 按 `DDNS_*` 生成 `/etc/ddns-harden/config.json`（目录 700、文件 600，token 不回显）→ 拿这份配置 `ddns --debug --config` 真跑一次自检 → 过了才 `ddns task --install --config`（默认 5 分钟续租）。四个参数缺一个就整段跳过——**连 ddns 都不装**、不写配置、不装任务（节点上不留用不上的包与空配置）；参数到位但字符集不合则停在写配置前，同样不装任务。若这台机器以前装过（`/etc/ddns-harden/config.json` 或 `ddns.timer` 还在），跳过时会多提示一句「仍在按旧配置跑」，要停掉跑 `--rollback`。
- unattended-upgrades 只自动装 security 源补丁 + needrestart 自动重启受库更新影响的服务；**有内核更新才重启**，时刻取 `REBOOT_TIME`（默认 05:00），有人登录时不重启。三台错开 `REBOOT_TIME` 避免同时掉线。
- journald 限额 `SystemMaxUse=200M`（保留至少 1G 空闲、最长 2 周）。
- fail2ban sshd jail：递增封禁（`bantime.increment`）+ recidive 惯犯 jail。Debian 12 精简安装没有 `/var/log/auth.log`，backend 走 journald。
- SSH 密钥化：候选公钥先单独 `ssh-keygen -lf` 验过**才写**进 authorized_keys（坏键/占位符不进文件）→ drop-in 关密码登录 + `AllowUsers` 白名单（默认只 root）+ `MaxStartups 5:30:20` 限速 + 关 X11/agent 转发 → `sshd -T` 断言真生效才 reload。没给公钥整段跳过、不关密码。被白名单挡在 SSH 外的现有登录账号（云镜像默认用户如 admin）会提示，不静默锁人。drop-in 写了但 `sshd -T` 仍不是 `no` 时，删掉 drop-in、不 reload，红字指出压制来源，按来源分两种给手工修法：**主配置 `Include` 之前那行**（sshd 只认第一个值，`sshd_config.d` 里怎么写都压不过）、**`sshd_config.d` 里按文件名排序比 `99-vnet-harden.conf` 靠前的文件**。修法按关键字注释整个文件里的 `PasswordAuthentication`（`sed 's/^[[:space:]]*PasswordAuthentication/#&/'`），不按行号——配置前后增删行或被重新生成过也注得对，`#` 后留着原值当线索；`50-cloud-init.conf` 另提示还要在 `/etc/cloud/cloud.cfg.d/99-disable-password-auth.cfg` 写 `ssh_pwauth: false`，否则重启会被改回来。脚本只打印步骤，不动这些别人的配置。
- ufw default-deny：顺序是先放 SSH（自动探测端口）→ 放业务口 → 管理口仅面板 IP → 才 default deny incoming + enable。任一条放行失败就中止、不 enable。
- AppArmor 启用断言（只读）：Debian 12 默认开，被内核参数关掉就提示；启用要改 cmdline 并重启，不代按。

```bash
curl -fsSL --connect-timeout 8 https://raw.githubusercontent.com/ProxyPanel/VNet-SSR/master/release/harden.sh \
  | SSH_PUBKEY='ssh-ed25519 AAAA…' PANEL_IP='面板出口IP' PUSH_PORT='30108' ALLOW_PORTS='10000-20000' bash -s --
```

| 变量 | 含义 |
| --- | --- |
| `SSH_PUBKEY` | 运维公钥，给了才关密码登录。一个服务商一把，在运维机上生成（脚本不在节点上生成私钥） |
| `SSH_ALLOW_USERS` | SSH 白名单，默认只 `root`；个别机器要用别的登录账号设 `'root <名字>'`。被挡外的现有登录账号会提示 |
| `ALLOW_PORTS` | 业务口放行规则，见下面的写法 |
| `PANEL_IP` | 面板访问节点时的**出口源 IP**（面板机 curl 节点时的源地址），不是面板域名解析到的 IP（可能隔 CDN）。给错管理口就被挡，节点收不到推送 |
| `PUSH_PORT` | 节点管理口（面板节点编辑页的 `push_port`），只听 TCP |
| `REBOOT_TIME` | 条件重启时刻，默认 05:00，三台各给不同值错开 |
| `DHCP=1` | 本机走 DHCP 续租时放行 UDP 67/68（默认自动探测，探不到跳过并提示） |
| `DDNS_DNS` | ddns 的提供方名（如 `dnspod`，取值见 `ddns --help`），**不是**要更新的域名 |
| `DDNS_ID` | 提供方账号（或子账号/令牌 ID） |
| `DDNS_TOKEN` | 提供方 API 密钥。只经环境变量/secrets 注入，不写脚本、不回显 |
| `DDNS_IPV4` | 要更新的域名，逗号分隔（如 `a.ddns.newfuture.cc,b.ddns.newfuture.cc`） |
| `AUTO_CONFIRM=1` | 跑完即确认、不起 10 分钟自动还原保险（**默认仍起保险**）。仅在你已验过密钥登录或自负锁死风险时用 |

`ALLOW_PORTS` 写法：逗号分隔，每项 `N` 或 `N-M`，可带 `/tcp`、`/udp`、`/both` 后缀，**不带后缀默认 tcp+udp 都放行**。多端口节点填面板「系统设置」的 `min_port`–`max_port` 段（`Helpers::getPort()` 在这个范围内分配用户端口，整段放行规则不随用户增减漂移）；单端口节点填那个端口；混合写 `'443,8388,10000-20000'`。

**防锁死（死人开关）**：关密码与开防火墙都有「配错一次连不回来」的路径，所以改完这两处**默认**会起一个 10 分钟 systemd 定时还原。已验过密钥登录或自负锁死风险时，加 `AUTO_CONFIRM=1`（或 `--auto-confirm`）跑完即确认、不起保险。默认流程：

1. 跑完脚本，保持当前会话别断（reload/enable 不掉已建立的连接）。
2. 开一个**新** SSH 会话，用密钥确认能登录。
3. 能登录 → 跑 `curl -fsSL <同一地址> | bash -s -- --confirm` 取消自动还原。
4. 登不上 → 什么都不做，10 分钟后自动删 sshd drop-in + 关 ufw，恢复密码登录。**别 reboot**（reboot 会丢 transient 定时器，保险就不触发了）。

子命令（写给 bash）：`--confirm` 取消保险；`--auto-confirm` 同 `AUTO_CONFIRM=1`；`--rollback` 退回；`--status` 只读读数；`--self-update` 拉最新脚本覆盖本地；`--version` 打印脚本版本；`--help`。

`--status` 一行一项（标签两字对齐 + 语义着色：绿=到位、黄=需注意/未到位、红=磁盘≥90% 或 EOL）：`系统`（发行版与 EOL 警示）/`节点`/`版本`/`上限`（fd）/`编号`（取自 config.json 的 node_id）/`拥塞`（cc + qdisc）/`时区`（+ NTP，取 systemd 的 `NTPSynchronized`：未启用 timesyncd、没网、刚开机未同步都会是 `no`；用 chrony/ntpd 替代 timesyncd 时它可能一直报 `no`，得用 `chronyc tracking` / `ntpq -p` 看真实状态）/`流量`（vnstat 今日 rx/tx）/`封禁`（fail2ban 在封数与 IP）/`防火`（ufw）/`认证`（`密码=` 与 `root=`；`sshd -T` 的 `without-password` 与 `prohibit-password` 是同一个值，统一显示 `prohibit-password`）/`磁盘`/`重启`/`保险`。没写 SSH drop-in 时多一行 `加固` 说明原因（没给公钥/公钥不对/`sshd -t` 不过/写了没生效）；「写了没生效」再跟一行 `压制`，只给文件与语句（如 `sshd_config: PasswordAuthentication yes`、`sshd_config.d/50-cloud-init.conf: PasswordAuthentication yes`），**不带行号**——行号只在跑的那会儿准，配置改过就会指错。

纯 `curl | bash -s` 不落盘，事后子命令需再拉一次。想免下载就存成本地命令：`curl -fsSL -o /usr/local/bin/vnet-harden <地址> && chmod +x /usr/local/bin/vnet-harden`，之后 `vnet-harden --status / --rollback`。本地副本会过期，用 `vnet-harden --self-update` 拉最新覆盖（`curl -f` + `bash -n` 校验，下载失败或语法不过**不覆盖**、旧版继续可用；stdin 形态没有本地文件时装到 `/usr/local/bin/vnet-harden`）。self-update 只升 harden 脚本自身，升 vnet 二进制走 `upgrade.sh`，别混。

`--rollback` 语义：删本脚本写的 drop-in、按清单逐条删自己加的 ufw 规则并还原改前默认策略与启用状态、还原补过的 sshd `Include`、删 `/etc/ddns-harden` 下的配置与 ddns 定时任务/缓存（`ddns task --uninstall` 认不出来时，按 unit 里写的配置路径认领后自己删，不留指向已删配置的 timer）。**不卸载已装的包**（vnstat/fail2ban/ufw/unattended-upgrades/needrestart/ddns 仍在，要彻底退 `apt remove`）；时区改回用 `timedatectl set-timezone Etc/UTC`。没有运行记录时 `--rollback` 不动 ufw，避免 wipe 掉别人预先存的规则。

EOL：Debian 11 已过安全支持期（LTS 2026-08-31 结束），自动补丁拿不到新补丁——**先升 Debian 12/13 再加固，顺序不能反**。脚本探到 EOL 会警告但照常做其余加固；非 Debian 直接停（不在未验证的发行版上代按防火墙/SSH），没有 systemd 也直接停（10 分钟还原保险与 ddns 定时续租都靠它）。

**首次上机验收**：脚本的 Linux 段（sshd/ufw/apt/systemd）未在开发机验证，开发机只跑了语法与纯函数测试（`bash release/harden_test.sh`）。先在一台**一次性 Debian 12/13 VPS** 上跑通下列清单，再上生产节点：

- [ ] `--status` 核对：ufw=active、`认证` 行 `密码=no root=prohibit-password`、fail2ban sshd jail 在、vnstat 统计的是出网网卡、`保险` 行在 `--confirm` 前显示计时中。
- [ ] 压制归因演练：在 `sshd_config` 的 `Include` 之前留一行 `PasswordAuthentication yes` 跑一遍，红字应说「主配置…Include 之前」并给 `f=…` + 按关键字注释的步骤；再把 `sshd_config.d/50-cloud-init.conf` 设成 `yes`、主配置那行注掉，红字应改说「按文件名排在 99-vnet-harden.conf 之前」并额外提示 cloud-init 的 `ssh_pwauth: false`。两处提示都不带行号，`--status` 的 `压制` 行同样只到文件与语句。
- [ ] ddns：`systemctl list-timers | grep ddns` 有 `ddns.timer`、`ddns task --status` 显示 Installed/Enabled，域名已解析到本机公网 IP；`--rollback` 后 timer 与 `/etc/ddns-harden` 都不在了。
- [ ] 新会话密钥登录成功 → `--confirm`；`systemctl list-timers` 里没有 `vnet-harden-revert`。
- [ ] 故意不 `--confirm`，等 10 分钟：`journalctl -t vnet-harden` 有自动还原行、密码登录恢复、ufw inactive。
- [ ] 面板推送可达：从面板机 curl 节点 `push_port` 通；节点 userList 能拉全量。
- [ ] 客户端实测：单端口/多端口各连一个用户，TCP 与 UDP（若 `is_udp=1`）都通。
- [ ] `--rollback` 后 ufw 回到改前状态、SSH 恢复密码登录、各 drop-in 删除。
- [ ] 重跑一次（幂等）：authorized_keys 不重复写、ufw 规则不重复、改前基线不被污染。
