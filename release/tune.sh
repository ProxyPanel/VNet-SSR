#!/bin/bash
# VNet 节点机一键调优：只写 /etc/sysctl.d、/etc/modules-load.d、/etc/modprobe.d、
# /etc/systemd/system/vnet.service.d 四处，全都由本文件生成，重跑覆盖，--rollback 一键删掉。
# 不动 sshd、不动防火墙、不自动重启 vnet（除非加 -r）。

CONF='/etc/sysctl.d/99-vnet-tune.conf'
MODLOAD='/etc/modules-load.d/vnet-bbr.conf'
CONNTRACK='/etc/modprobe.d/vnet-conntrack.conf'
DROPIN='/etc/systemd/system/vnet.service.d/99-tune.conf'

NR_OPEN=2097152
LIMIT_NOFILE=1048576
CONNTRACK_MAX=262144
CONNTRACK_HASH=65536

RED=31m
GREEN=32m
YELLOW=33m
BLUE=36m
colorEcho() { echo -e "\033[${1}${@:2}\033[0m" 1>&2; }

# 非 root 以 0 退出：调用方按 rc 判失败，返回 1 会把「什么都没做」报成「做失败了」
[[ ${EUID} -ne 0 ]] && { colorEcho ${YELLOW} "不是 root，这次什么都没改（写 sysctl、modprobe.d 与 unit 都要 root）。"; exit 0; }

if [[ ${1:-} == '--rollback' ]]; then
  rm -f "$CONF" "$MODLOAD" "$CONNTRACK" "$DROPIN"
  [[ -d /etc/systemd/system/vnet.service.d ]] && rmdir /etc/systemd/system/vnet.service.d 2>/dev/null
  systemctl daemon-reload 2>/dev/null
  sysctl --system >/dev/null 2>&1
  colorEcho ${GREEN} "已删除本脚本写的四处配置并重新加载。"
  colorEcho ${YELLOW} "文件描述符上限要重启 vnet 才回到原值：systemctl restart vnet"
  exit 0
fi

RESTART=0
[[ ${1:-} == '-r' || ${1:-} == '--restart' ]] && RESTART=1

# systemctl show 报的是配置值；配置超内核允许的那个数会被直接拒掉，所以另取进程真正的上限
procOpenFiles() {
  local pid
  pid=$(systemctl show -p MainPID --value vnet 2>/dev/null)
  if ! [[ "$pid" =~ ^[0-9]+$ ]] || ((pid == 0)); then
    echo '未运行'
    return 0
  fi
  awk '/Max open files/ { print $4"/"$5 }' "/proc/${pid}/limits" 2>/dev/null || echo '取不到'
}

before_cc=$(sysctl -qn net.ipv4.tcp_congestion_control 2>/dev/null)
before_qd=$(sysctl -qn net.core.default_qdisc 2>/dev/null)
before_ct=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)
before_cte=$(cat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established 2>/dev/null)
before_mp=$(cat /proc/sys/net/ipv4/tcp_mtu_probing 2>/dev/null)
before_sc=$(cat /proc/sys/net/core/somaxconn 2>/dev/null)
before_tr=$(cat /proc/sys/net/ipv4/tcp_tw_reuse 2>/dev/null)
before_ts=$(cat /proc/sys/net/ipv4/tcp_timestamps 2>/dev/null)
before_nro=$(cat /proc/sys/fs/nr_open 2>/dev/null)
before_fd=$(systemctl show vnet -p LimitNOFILE --value 2>/dev/null)
before_real=$(procOpenFiles)

colorEcho ${BLUE} "调优前的值："
echo "  拥塞控制=${before_cc:-取不到} qdisc=${before_qd:-取不到} mtu_probing=${before_mp:-取不到}"
echo "  conntrack_max=${before_ct:-未加载} tcp_established=${before_cte:-未加载} nr_open=${before_nro:-取不到}"
echo "  somaxconn=${before_sc:-取不到} tw_reuse=${before_tr:-取不到} timestamps=${before_ts:-取不到}"
echo "  vnet 连接数上限：配置=${before_fd:-服务不存在} 进程实际=${before_real}"

# 拥塞控制：已经是任一 BBR 变体就不动它，覆盖成原生 bbr 等于把装机者故意选的东西降级
# 内核不带 tcp_bbr 模块（OpenVZ 这类共享内核）时整块跳过，不留下点了报错也不生效的两行
BBR=0
QD=0
case "$before_cc" in
bbr*)
  colorEcho ${GREEN} "拥塞控制已经是 ${before_cc}，这条不动（连 qdisc 一起保留原样）。"
  ;;
*)
  if modprobe tcp_bbr 2>/dev/null && sysctl -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1; then
    BBR=1
    sysctl -w net.core.default_qdisc=fq >/dev/null 2>&1 && QD=1 ||
      colorEcho ${YELLOW} "BBR 已生效但 fq 挂不上（内核没带或已被别的 qdisc 占住），整形那行不写。"
  else
    colorEcho ${YELLOW} "这台机的内核改不了拥塞控制（多半是 OpenVZ 共享内核），BBR 那两行不写。"
  fi
  ;;
esac

umask 022
mkdir -p /etc/systemd/system/vnet.service.d
{
  echo '# 由 release/tune.sh 生成，删掉这个文件即可还原'
  ((BBR)) && echo 'net.ipv4.tcp_congestion_control = bbr'
  ((QD)) && echo 'net.core.default_qdisc = fq'
  # 长连接闲置后不再从慢启动重来，订阅客户端隔一会儿再用最明显
  echo 'net.ipv4.tcp_slow_start_after_idle = 0'
  # 跨境线路上中间设备常把 packet-too-big 丢掉（MTU 黑洞）：握手正常、大包卡死。
  # 开探测让内核自己找得到达对端的可行 MTU，代价只是偶尔多几个探测包
  echo 'net.ipv4.tcp_mtu_probing = 1'
  echo 'net.ipv4.tcp_keepalive_time = 300'
  echo 'net.ipv4.tcp_keepalive_intvl = 30'
  echo 'net.ipv4.tcp_keepalive_probes = 4'
  echo 'net.core.netdev_max_backlog = 8192'
  echo 'net.ipv4.tcp_max_syn_backlog = 4096'
  # accept 队列上限：tcp_max_syn_backlog 只管半连接，已完成握手但没人 accept 的连接靠这个队列
  echo 'net.core.somaxconn = 32768'
  echo 'net.core.rmem_max = 16777216'
  echo 'net.core.wmem_max = 16777216'
  echo 'net.ipv4.tcp_rmem = 4096 131072 16777216'
  echo 'net.ipv4.tcp_wmem = 4096 131072 16777216'
  echo 'net.ipv4.ip_local_port_range = 20000 60999'
  # 主动连上游时复用 TIME_WAIT 里的四元组，省本地端口（要 tcp_timestamps=1 才生效，下面有检查）
  echo 'net.ipv4.tcp_tw_reuse = 1'
  echo "fs.nr_open = $NR_OPEN"
  # 这几行是防中间人重定向与源路由，不改连通性
  echo 'net.ipv4.conf.all.accept_source_route = 0'
  echo 'net.ipv4.conf.default.accept_source_route = 0'
  echo 'net.ipv4.conf.all.accept_redirects = 0'
  echo 'net.ipv4.conf.default.accept_redirects = 0'
  echo 'net.ipv4.conf.all.send_redirects = 0'
  echo 'net.ipv4.conf.all.log_martians = 1'
  echo 'kernel.kptr_restrict = 2'
  echo 'kernel.dmesg_restrict = 1'
  echo 'fs.protected_symlinks = 1'
  echo 'fs.protected_hardlinks = 1'
} >"$CONF"

if ((BBR)); then
  echo tcp_bbr >"$MODLOAD"
else
  rm -f "$MODLOAD"
fi

# conntrack 只有模块在跑才写，否则这些 net.netfilter.* 会让 sysctl --system 报无关键
if [[ -e /proc/sys/net/netfilter/nf_conntrack_max ]]; then
  echo 'net.netfilter.nf_conntrack_max = 262144' >>"$CONF"
  # 只调大上限不够：默认 established 要占 5 天、time_wait 120s，表项回收慢，被打时先 table full。
  # 代理长连接有 keepalive(300s) 保活，1800s 足够；UDP 两行本来就是默认值，写出来是为了将来改得动
  echo 'net.netfilter.nf_conntrack_tcp_timeout_established = 1800' >>"$CONF"
  echo 'net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30' >>"$CONF"
  echo 'net.netfilter.nf_conntrack_udp_timeout = 30' >>"$CONF"
  echo 'net.netfilter.nf_conntrack_udp_timeout_stream = 120' >>"$CONF"
  echo "options nf_conntrack hashsize=$CONNTRACK_HASH" >"$CONNTRACK"
else
  rm -f "$CONNTRACK"
fi

# LimitNOFILE 高于 fs.nr_open 就是假上限：按内核允许的那个数落地（存量安装的 unit 可能带着旧的大值）
cat >"$DROPIN" <<EOF
# 由 release/tune.sh 生成，--rollback 删除
[Service]
LimitNOFILE=$LIMIT_NOFILE
EOF

sysctl --system >/dev/null 2>&1
systemctl daemon-reload 2>/dev/null

# tcp_tw_reuse 只在双方都带时间戳时生效：哪个文件把 tcp_timestamps 关了，这一行就是死配置。
# 只提示，不替他改——改回去会和关它的人打架，破坏“只动自己写的文件”
if [[ $(cat /proc/sys/net/ipv4/tcp_timestamps 2>/dev/null) == '0' ]]; then
  colorEcho ${YELLOW} "tcp_timestamps=0：tcp_tw_reuse 因此不生效（TW 复用靠时间戳判重），查 /etc/sysctl.d 里是谁关的。"
fi

# 时间不同步会让流量批次去重和日志对齐出错；装不上就只报一行，不挡后面的活
if command -v timedatectl >/dev/null 2>&1 && [[ $(timedatectl show -p NTPSynchronized --value 2>/dev/null) == 'no' ]]; then
  # 已经装过就别再报「装好了」：同步要几十秒才到位，重跑时会连着好几轮都显示 no
  if systemctl is-active chronyd >/dev/null 2>&1 || systemctl is-enabled chrony >/dev/null 2>&1 || command -v chronyd >/dev/null 2>&1; then
    colorEcho ${YELLOW} "chrony 已经在机上但时间还没同步上：看 systemctl status chrony，以及上游 123/udp 有没有被挡。"
  elif apt-get -y -qq install chrony </dev/null >/dev/null 2>&1 && systemctl enable --now chrony >/dev/null 2>&1; then
    colorEcho ${GREEN} "装好并启动了 chrony，时间开始同步。"
  else
    colorEcho ${YELLOW} "时间还没同步，chrony 也没装上（EOL 机器多半是软件源过期）：修好 /etc/apt/sources.list 再跑 apt-get install -y chrony。"
  fi
fi

if ((RESTART)); then
  systemctl restart vnet && colorEcho ${GREEN} "已重启 vnet，进程现在的上限是 $(procOpenFiles)。"
elif [[ "$before_real" == "$LIMIT_NOFILE" ]]; then
  colorEcho ${BLUE} "进程本来就已经是 ${LIMIT_NOFILE} 个 fd，这步不用重启。"
elif [[ "$before_real" == "未运行" || "$before_real" == "取不到" ]]; then
  colorEcho ${BLUE} "现在没有 vnet 进程在跑，drop-in 已写好，下次启动自然带上。"
else
  colorEcho ${YELLOW} "会断掉当前在线连接的一步没做：fd 上限要从 ${before_real} 变成 ${LIMIT_NOFILE} 得 systemctl restart vnet（或者重跑本脚本加 -r）。"
fi

colorEcho ${BLUE} "调优后的值："
after_cc=$(sysctl -qn net.ipv4.tcp_congestion_control 2>/dev/null)
after_qd=$(sysctl -qn net.core.default_qdisc 2>/dev/null)
after_ct=$(cat /proc/sys/net/netfilter/nf_conntrack_max 2>/dev/null)
after_cte=$(cat /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established 2>/dev/null)
after_mp=$(cat /proc/sys/net/ipv4/tcp_mtu_probing 2>/dev/null)
after_sc=$(cat /proc/sys/net/core/somaxconn 2>/dev/null)
after_tr=$(cat /proc/sys/net/ipv4/tcp_tw_reuse 2>/dev/null)
after_ts=$(cat /proc/sys/net/ipv4/tcp_timestamps 2>/dev/null)
after_nro=$(cat /proc/sys/fs/nr_open 2>/dev/null)
echo "  拥塞控制=${after_cc:-取不到} qdisc=${after_qd:-取不到} mtu_probing=${after_mp:-取不到}"
echo "  conntrack_max=${after_ct:-未加载} tcp_established=${after_cte:-未加载} nr_open=${after_nro:-取不到}"
echo "  somaxconn=${after_sc:-取不到} tw_reuse=${after_tr:-取不到} timestamps=${after_ts:-取不到}"
echo "  vnet 连接数上限：配置=$(systemctl show vnet -p LimitNOFILE --value 2>/dev/null) 进程实际=$(procOpenFiles)"
echo "  配置文件：$CONF"
echo "  一键还原：bash release/tune.sh --rollback"
exit 0
