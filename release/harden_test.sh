#!/bin/bash
# harden.sh 纯函数测试：只测不碰系统的解析/校验函数，含反向对照（坏输入必须被拒）。
# Git Bash 即可跑：bash release/harden_test.sh
# Linux 相关段（sshd/ufw/apt/systemd）真机未验，验收清单见 docs/operations.md「系统加固」一节。
set -u
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=harden.sh
. "$DIR/harden.sh"

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); }
bad() {
  FAIL=$((FAIL + 1))
  echo "FAIL: $1" >&2
}
expect_eq() {
  local desc="$1" want="$2" got="$3"
  if [[ "$want" == "$got" ]]; then ok; else bad "$desc: want [$want] got [$got]"; fi
}
expect_reject() {
  local desc="$1"
  shift
  if "$@" >/dev/null 2>&1; then bad "$desc: 应拒绝但通过了"; else ok; fi
}
expect_has() {
  local desc="$1" needle="$2" hay="$3"
  if [[ "$hay" == *"$needle"* ]]; then ok; else bad "$desc: 缺 [$needle] got [$hay]"; fi
}

# parse_ports 正向
expect_eq '单端口默认both' $'443/tcp\n443/udp' "$(parse_ports '443')"
expect_eq '端口段' $'10000:20000/tcp\n10000:20000/udp' "$(parse_ports '10000-20000')"
expect_eq '混合' $'443/tcp\n443/udp\n8388/tcp\n8388/udp\n10000:20000/tcp\n10000:20000/udp' "$(parse_ports '443,8388,10000-20000')"
expect_eq '指定tcp' '53/tcp' "$(parse_ports '53/tcp')"
expect_eq '指定udp' '53/udp' "$(parse_ports '53/udp')"
expect_eq '段带proto' '10000:20000/tcp' "$(parse_ports '10000-20000/tcp')"
expect_eq '带空格' $'443/tcp\n443/udp' "$(parse_ports ' 443 ')"
expect_eq '尾逗号' $'443/tcp\n443/udp' "$(parse_ports '443,')"
expect_eq '边界1' $'1/tcp\n1/udp' "$(parse_ports '1')"
expect_eq '边界65535' $'65535/tcp\n65535/udp' "$(parse_ports '65535')"

# parse_ports 反向：这些都必须返回非 0
expect_reject '空串' parse_ports ''
expect_reject '非数字' parse_ports 'abc'
expect_reject '端口0' parse_ports '0'
expect_reject '端口65536' parse_ports '65536'
expect_reject '端口99999' parse_ports '99999'
expect_reject '段越界' parse_ports '70000-80000'
expect_reject '段起大于止' parse_ports '20000-10000'
expect_reject '未知协议' parse_ports '443/sctp'
expect_reject '空协议' parse_ports '443/'
expect_reject '多重段' parse_ports '1-2-3'
expect_reject '段含非数字' parse_ports 'a-b'
expect_reject '全逗号' parse_ports ','
expect_reject '逗号加空格' parse_ports ' , '

# valid_port
valid_port 22 && ok || bad '22 应合法'
valid_port 65535 && ok || bad '65535 应合法'
expect_reject 'port0' valid_port 0
expect_reject 'port65536' valid_port 65536
expect_reject 'portabc' valid_port abc
expect_reject 'port空' valid_port ''

# valid_ip
valid_ip 1.2.3.4 && ok || bad '1.2.3.4 应合法'
valid_ip 255.255.255.255 && ok || bad '255.255.255.255 应合法'
valid_ip '2001:db8::1' && ok || bad 'IPv6 应合法'
expect_reject 'ip256' valid_ip 256.1.1.1
expect_reject 'ip三段' valid_ip 1.2.3
expect_reject 'ip串' valid_ip 'not-an-ip'
expect_reject 'ip空' valid_ip ''

# 公钥可解析判据：占位符/空串必须拒；真生成的 ed25519 公钥必须过。
# 真机曾把示例占位 'ssh-ed25519 AAAA…' 当真钥传，旧逻辑先写后验留下垃圾；现验过才写
expect_reject '占位公钥' pubkey_parseable 'ssh-ed25519 AAAA…'
expect_reject '空公钥' pubkey_parseable ''
expect_reject '乱串公钥' pubkey_parseable 'not-a-key'
if command -v ssh-keygen >/dev/null 2>&1; then
  kt=$(mktemp -d)
  if ssh-keygen -t ed25519 -N '' -f "$kt/k" >/dev/null 2>&1; then
    if pubkey_parseable "$(cat "$kt/k.pub")"; then ok; else bad '真 ed25519 公钥应可解析'; fi
  else
    bad '测试用密钥生成失败'
  fi
  rm -rf "$kt"
else
  echo '（跳过真公钥用例：无 ssh-keygen）' >&2
fi

# SSH 白名单：默认只 root；SSH_ALLOW_USERS 覆盖（个别机器要用别的登录账号）
expect_eq '白名单默认root' 'root' "$(ssh_allow_users)"
expect_eq '白名单覆盖' 'root ops' "$(SSH_ALLOW_USERS='root ops' ssh_allow_users)"

# 压制来源定位：sshd 同名关键字只认第一个值，sshd_config.d 按文件名排序读；
# 主配置 Include 之前的那行更靠前。--status 与 sec_ssh 的红字都靠它指出文件:行号
pd=$(mktemp -d)
printf 'Include /etc/ssh/sshd_config.d/*.conf\n' >"$pd/sshd_config"
printf 'PasswordAuthentication yes\n' >"$pd/50-cloud-init.conf"
printf 'PasswordAuthentication no\n' >"$pd/99-vnet-harden.conf"
expect_eq 'pa压制来源' "$pd/50-cloud-init.conf:1: PasswordAuthentication yes" "$(ssh_pa_override "$pd/sshd_config" "$pd")"
printf 'PasswordAuthentication yes\nInclude /etc/ssh/sshd_config.d/*.conf\n' >"$pd/sshd_config"
expect_eq 'pa主配置更靠前' "$pd/sshd_config:1: PasswordAuthentication yes" "$(ssh_pa_override "$pd/sshd_config" "$pd")"
printf 'PasswordAuthentication no\n' >"$pd/50-cloud-init.conf"
printf 'Include /etc/ssh/sshd_config.d/*.conf\n' >"$pd/sshd_config"
expect_eq 'pa无压制' '' "$(ssh_pa_override "$pd/sshd_config" "$pd")"

# 压制提示按来源分两种说法，各带备份：主配置 Include 之前 vs sshd_config.d 里排序靠前的文件
hint=$(ssh_pa_hint "$pd/sshd_config:1: PasswordAuthentication yes" "$pd/sshd_config")
expect_has '提示主配置来源' '压住它的是主配置（Include 之前' "$hint"
expect_has '提示主配置变量' "f=$pd/sshd_config" "$hint"
expect_has '提示函数备份' 'cp -a "$f"{,.$(date +%F)}' "$hint"
# 修法按关键字、不按行号：配置前后增删几行、被重新生成过，也不会注释错地方
expect_has '提示按关键字' "sed -i 's/^[[:space:]]*PasswordAuthentication/#&/' \"\$f\"" "$hint"
expect_has '提示不按行号' '不按行号' "$hint"
hint=$(ssh_pa_hint "$pd/50-cloud-init.conf:1: PasswordAuthentication yes" "$pd/sshd_config")
expect_has '提示d目录来源' '压住它的是 sshd_config.d/50-cloud-init.conf' "$hint"
expect_has '提示d目录变量' "f=$pd/50-cloud-init.conf" "$hint"
expect_has '提示cloud-init回写' 'ssh_pwauth: false' "$hint"
expect_has '提示重跑' '带 SSH_PUBKEY 重跑' "$hint"

# --status 的压制行：路径缩成相对、行号去掉（配置改过之后存下的行号会指错）
expect_eq 'status压制去行号' 'sshd_config: PasswordAuthentication yes' "$(ssh_pa_label '/etc/ssh/sshd_config:3: PasswordAuthentication yes')"
expect_eq 'status压制d目录' 'sshd_config.d/50-cloud-init.conf: PasswordAuthentication yes' "$(ssh_pa_label '/etc/ssh/sshd_config.d/50-cloud-init.conf:1: PasswordAuthentication yes')"
expect_eq 'status压制空' '' "$(ssh_pa_label '')"

# kernel_origin：第三方内核要在读数里区分出来（只认 uname -r 的特征串）
expect_eq '内核来源xanmod' '第三方 xanmod' "$(kernel_origin '6.12.9-x64v3-xanmod1')"
expect_eq '内核来源bbrplus' '第三方 bbrplus' "$(kernel_origin '5.10.27-bbrplus')"
expect_eq '内核来源elrepo' '第三方 elrepo' "$(kernel_origin '6.11.3-1.el9.elrepo.x86_64')"
expect_eq '内核来源debian' '发行版' "$(kernel_origin '6.12.48-amd64')"
expect_eq '内核来源ubuntu' '发行版' "$(kernel_origin '6.8.0-45-generic')"
expect_eq '内核来源空' '取不到' "$(kernel_origin '')"

# ddns：没给全参数就整段跳过，连 ddns 都不装（真机上装了也是白装）
out=$(DDNS_DNS= DDNS_ID= DDNS_TOKEN= DDNS_IPV4= sec_ddns 2>&1 >/dev/null)
expect_has 'ddns段标题' '== DDNS 配置 ==' "$out"
expect_has 'ddns缺参跳过' '不装 ddns' "$out"
if [[ "$out" == *'ddns 就绪'* ]]; then bad 'ddns缺参不应探测/安装 ddns'; else ok; fi
if [[ "$out" == *'仍在按旧配置跑'* ]]; then bad '没残留时不该提旧任务'; else ok; fi

# 以前装过 ddns（配置还在）：缺参跳过时要提醒它仍在按旧配置续租、如何停
pd2=$(mktemp -d)
: >"$pd2/config.json"
out=$(DDNS_CONFIG="$pd2/config.json" DDNS_DNS= DDNS_ID= DDNS_TOKEN= DDNS_IPV4= sec_ddns 2>&1 >/dev/null)
expect_has 'ddns残留旧任务提示' '仍在按旧配置跑' "$out"
expect_has 'ddns残留停用提示' 'harden.sh --rollback' "$out"
rm -rf "$pd2"

# 只给 DDNS_IPV6 也算给了域名：缺凭据时跳过的原因里不该再列 DDNS_IPV4/IPV6
out=$(DDNS_DNS= DDNS_ID= DDNS_TOKEN= DDNS_IPV6='v6.example.com' sec_ddns 2>&1 >/dev/null)
expect_has 'ddns仅v6仍跳过' '不装 ddns' "$out"
if [[ "$out" == *'DDNS_IPV4/IPV6'* ]]; then bad '只给 v6 不该报缺域名'; else ok; fi

# 配置生成：启用的族才写 ipvN 与 indexN=public（默认 default 在多网卡/VPN 上会抓到怪 IP）
cfg4=$(ddns_config_text dnspod id tok 'a.example.com, b.example.com' '')
expect_has 'ddns配置v4域名' '"ipv4": ["a.example.com", "b.example.com"]' "$cfg4"
expect_has 'ddns配置index4' '"index4": "public"' "$cfg4"
if [[ "$cfg4" == *'index6'* || "$cfg4" == *'"ipv6"'* ]]; then bad '只给 v4 不该写 v6/index6'; else ok; fi

cfg6=$(ddns_config_text dnspod id tok '' 'v6.example.com')
expect_has 'ddns配置v6域名' '"ipv6": ["v6.example.com"]' "$cfg6"
expect_has 'ddns配置index6' '"index6": "public"' "$cfg6"
if [[ "$cfg6" == *'index4'* || "$cfg6" == *'"ipv4"'* ]]; then bad '只给 v6 不该写 v4/index4'; else ok; fi

cfgboth=$(ddns_config_text dnspod id tok 'a.example.com' 'v6.example.com')
expect_has '双栈index4' '"index4": "public"' "$cfgboth"
expect_has '双栈index6' '"index6": "public"' "$cfgboth"
if command -v python3 >/dev/null 2>&1 && python3 -c 'import json' >/dev/null 2>&1; then
  cfgtmp=$(mktemp)
  printf '%s\n' "$cfgboth" >"$cfgtmp"
  if python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); assert d["index4"]=="public" and d["index6"]=="public"' "$cfgtmp" 2>/dev/null; then ok; else bad 'ddns 配置不是合法 JSON'; fi
  rm -f "$cfgtmp"
fi

# 坏域名/两族都空：返回非 0，调用方据此不写配置
expect_reject 'ddns坏域名' ddns_config_text dnspod id tok 'bad!domain' ''
expect_reject 'ddns坏v6域名' ddns_config_text dnspod id tok '' 'bad!domain'
expect_reject 'ddns两族都空' ddns_config_text dnspod id tok '' ''
rm -rf "$pd"

# 锁死保险判定：真改了 ssh/防火墙才起；AUTO_CONFIRM=1 一律不起
STATE_KV[SSH_HARDENED]=1
STATE_KV[UFW_ENABLED]=0
if should_arm_revert; then ok; else bad '改了 ssh 应起保险'; fi
if AUTO_CONFIRM=1 should_arm_revert; then bad 'AUTO_CONFIRM 不应起保险'; else ok; fi
STATE_KV[SSH_HARDENED]=0
STATE_KV[UFW_ENABLED]=1
if should_arm_revert; then ok; else bad '开了防火墙应起保险'; fi
STATE_KV[UFW_ENABLED]=0
if should_arm_revert; then bad '都没改不应起保险'; else ok; fi

# self-update 覆盖目标：空/不存在→默认安装路径；真实文件→其 realpath
expect_eq 'selfupdate默认路径' '/usr/local/bin/vnet-harden' "$(self_update_target '')"
expect_eq 'selfupdate不存在文件' '/usr/local/bin/vnet-harden' "$(self_update_target '/no/such/file.sh')"
expect_eq 'selfupdate真实文件' "$(realpath "$DIR/harden.sh")" "$(self_update_target "$DIR/harden.sh")"
# 版本标记存在：self-update 靠它比对旧新与校验下载内容
if [[ -n "$HARDEN_VERSION" ]]; then ok; else bad 'HARDEN_VERSION 不应为空'; fi

# 节点 id 解析：从配置取 node_id；缺键/缺文件返回空
nj=$(mktemp)
printf '{"api_host":"https://p.example","node_id":7,"key":"k"}\n' >"$nj"
expect_eq 'node_id解析' '7' "$(node_id_from_config "$nj")"
printf '{"api_host":"https://p.example"}\n' >"$nj"
expect_eq 'node_id缺键' '' "$(node_id_from_config "$nj")"
rm -f "$nj"
expect_eq 'node_id缺文件' '' "$(node_id_from_config '/no/such/config.json')"

# DHCP 探测：配置面用临时文件驱动，运行面用 ss/netstat 输出样本判 UDP 68
NETD_RE='^[[:space:]]*DHCP[[:space:]]*=[[:space:]]*(yes|ipv4|ipv6|both)([[:space:]]|$)'
IFACE_RE='^[[:space:]]*iface[[:space:]]+[^[:space:]]+[[:space:]]+inet6?[[:space:]]+(dhcp|auto)([[:space:]]|$)'
NM_RE='^[[:space:]]*method[[:space:]]*=[[:space:]]*auto([[:space:]]|$)'
NP_RE='^[[:space:]]*dhcp[46]?[[:space:]]*:[[:space:]]*true([[:space:]]|$)'
dp=$(mktemp -d)
printf '[Match]\nName=eth0\n\n[Network]\nDHCP=ipv4\n' >"$dp/10-netplan-eth0.network"
printf '[Match]\nName=eth1\n\n[Network]\nDHCP=no\n' >"$dp/static.network"
printf 'auto eth0\niface eth0 inet dhcp\n' >"$dp/interfaces"
printf 'auto eth1\niface eth1 inet static\n' >"$dp/interfaces-static"
printf '[connection]\nid=Wired\n[ipv4]\nmethod=auto\n' >"$dp/eth0.nmconnection"
printf '[ipv4]\nmethod=manual\n' >"$dp/static.nmconnection"
printf 'network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: true\n' >"$dp/01-netcfg.yaml"
printf 'network:\n  version: 2\n  ethernets:\n    eth1:\n      dhcp4: false\n' >"$dp/static.yaml"
if dhcp_conf_has "$NETD_RE" "$dp/static.network" "$dp/10-netplan-eth0.network"; then ok; else bad 'networkd DHCP=ipv4 应识别'; fi
expect_reject 'networkd DHCP=no' dhcp_conf_has "$NETD_RE" "$dp/static.network"
if dhcp_conf_has "$IFACE_RE" "$dp/interfaces"; then ok; else bad 'ifupdown inet dhcp 应识别'; fi
expect_reject 'ifupdown static' dhcp_conf_has "$IFACE_RE" "$dp/interfaces-static"
if dhcp_conf_has "$NM_RE" "$dp/eth0.nmconnection"; then ok; else bad 'NetworkManager method=auto 应识别'; fi
expect_reject 'NetworkManager method=manual' dhcp_conf_has "$NM_RE" "$dp/static.nmconnection"
if dhcp_conf_has "$NP_RE" "$dp/01-netcfg.yaml"; then ok; else bad 'netplan dhcp4:true 应识别'; fi
expect_reject 'netplan dhcp4:false' dhcp_conf_has "$NP_RE" "$dp/static.yaml"
expect_reject '配置文件不存在' dhcp_conf_has "$NETD_RE" "$dp/no-such.network"
rm -rf "$dp"

ss_v4=$'State Recv-Q Send-Q Local Address:Port Peer Address:Port\nUNCONN 0 0 0.0.0.0:68 0.0.0.0:*'
ss_v6=$'State Recv-Q Send-Q Local Address:Port Peer Address:Port\nUNCONN 0 0 [::]:68 [::]:*'
ss_67=$'State Recv-Q Send-Q Local Address:Port Peer Address:Port\nUNCONN 0 0 0.0.0.0:67 0.0.0.0:*'
ss_peer=$'State Recv-Q Send-Q Local Address:Port Peer Address:Port\nUNCONN 0 0 127.0.0.1:53 0.0.0.0:68'
netstat_v4=$'Proto Recv-Q Send-Q Local Address Foreign Address State\nudp 0 0 0.0.0.0:68 0.0.0.0:*'
dhcp_udp68_bound "$ss_v4" && ok || bad 'ss 本机 0.0.0.0:68 应识别'
dhcp_udp68_bound "$ss_v6" && ok || bad 'ss 本机 [::]:68 应识别'
dhcp_udp68_bound "$netstat_v4" && ok || bad 'netstat 本机 0.0.0.0:68 应识别'
expect_reject 'ss 只有 67 不算 DHCP' dhcp_udp68_bound "$ss_67"
expect_reject 'ss 对端 68 不算 DHCP' dhcp_udp68_bound "$ss_peer"
expect_reject 'ss 空输出' dhcp_udp68_bound ''

# DHCP=1 必须短路所有探测，且回报来源（sec_firewall 会把它打进日志）
det=$(DHCP=1 dhcp_probe)
expect_eq 'DHCP=1 来源' 'DHCP=1 指定' "$det"
DHCP=1 detect_dhcp && ok || bad 'DHCP=1 应直接认定有 DHCP'

# 回归：两种真实调用形态都必须真跑 main。source-guard 曾把 stdin（curl|bash -s）整条跳过，
# 表现为下载成功却静默无输出；纯函数测试走源进路径覆盖不到它，故在这里直接驱动两种形态
stdin_out=$(bash -s -- --help <"$DIR/harden.sh" 2>&1)
if [[ "$stdin_out" == *'节点机一键前置配置'* ]]; then ok; else bad 'stdin(bash -s) 形态没跑 main'; fi
file_out=$(bash "$DIR/harden.sh" --help 2>&1)
if [[ "$file_out" == *'节点机一键前置配置'* ]]; then ok; else bad '文件(bash harden.sh) 形态没跑 main'; fi

echo "PASS=$PASS FAIL=$FAIL"
[[ $FAIL -eq 0 ]]