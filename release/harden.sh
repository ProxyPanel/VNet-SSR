#!/bin/bash

# 下发地址：https://raw.githubusercontent.com/ProxyPanel/VNet-SSR/master/release/harden.sh
#
# 节点机一键前置配置 + 安全加固。与 deploy/tune/upgrade 同族：幂等重跑、只写自己生成的配置、
# --rollback 退回、改前改后打印读数。deploy.sh 的边界不动（装机不隐含改整机），本脚本是独立的一步。
#
# 一键（环境变量写在 bash 前，与 WEB_API/NODE_ID 同位置；开关写给 bash 不是写给 curl）：
#   curl -fsSL --connect-timeout 8 https://raw.githubusercontent.com/ProxyPanel/VNet-SSR/master/release/harden.sh \
#     | SSH_PUBKEY='ssh-ed25519 AAAA…' PANEL_IP='面板IP' PUSH_PORT='30108' ALLOW_PORTS='10000-20000' bash -s --
#
# 环境变量：
#   SSH_PUBKEY    运维公钥（一个服务商一把，在运维机上生成）。给了才关密码登录；没给整段跳过、只提示。
#   ALLOW_PORTS   业务口放行规则，逗号分隔：'443'（单端口）、'10000-20000'（多端口段，取面板系统设置的
#                 min_port/max_port）、'443,8388,10000-20000'（混合）。每项可带 /tcp /udp /both 后缀，
#                 不带后缀默认 tcp+udp 都放行。
#   PANEL_IP      面板出口 IP；管理口 PUSH_PORT 只对它开放。
#   PUSH_PORT     节点管理口（面板节点编辑页的 push_port），只听 TCP。
#   REBOOT_TIME   条件重启时刻，默认 05:00；三台错开就各给不同值（如 05:00/05:20/05:40）。
#   DHCP=1        本机走 DHCP 续租时放行 UDP 67/68（默认自动探测，探不到就跳过并提示）。
#   DDNS_DNS      ddns 的提供方名（示例：dnspod，取值见 ddns --help）；DDNS_ID / DDNS_TOKEN 是提供方给的凭据；
#   DDNS_IPV4     要更新的域名，逗号分隔（如 'a.ddns.newfuture.cc,b.ddns.newfuture.cc'）。
#                 四个缺一个就整段跳过（不装 ddns、不写配置、不装任务）；值只从环境变量/secrets 注入，不写进脚本。
#
# 子命令（写给 bash）：
#   --confirm     开新会话确认能登录后跑它，取消 10 分钟自动还原（死人开关）。
#   --rollback    删本脚本写的配置、还原 ufw 与 sshd 到改前、清 ddns 配置/任务/缓存；不卸载已装的包。
#   --status      只读一条读数：服务/版本/fd/拥塞控制/今日流量/封禁数/磁盘/待重启/ufw/ssh 认证方式。
#   -h, --help    本帮助。
#
# 退出码：0 成功（含「什么都没改」）；1 环境错误（非 root/非 Debian/缺必要变量且无法安全继续）。
#
# 防锁死：关密码登录与 ufw default-deny 都有「配错一次连不回来」的路径。本脚本改完这两处会起一个
# 10 分钟 systemd 定时还原（删 sshd drop-in + 关 ufw），你开新会话确认能登录后跑 --confirm 取消；
# 不确认就自动退回。sshd 配置先用 sshd -T 断言真生效才 reload，公钥先用 ssh-keygen -lf 验过才写。

RAW_BASE='https://raw.githubusercontent.com/ProxyPanel/VNet-SSR/master'
HARDEN_VERSION='2026-11-21.8'

STATE_DIR='/etc/vnet-harden'
STATE_FILE="$STATE_DIR/state.env"
UFW_RULES_FILE="$STATE_DIR/ufw_rules"
REVERT_HELPER="$STATE_DIR/revert.sh"
SSH_DROPIN='/etc/ssh/sshd_config.d/99-vnet-harden.conf'
JOURNAL_DROPIN='/etc/systemd/journald.conf.d/99-vnet-harden.conf'
UU_DROPIN='/etc/apt/apt.conf.d/99-vnet-harden-auto-upgrades'
NEEDRESTART_DROPIN='/etc/needrestart/conf.d/99-vnet-harden.conf'
F2B_DROPIN='/etc/fail2ban/jail.d/99-vnet-harden.conf'
REVERT_UNIT='vnet-harden-revert'
REBOOT_TIME_DEFAULT='05:00'
DDNS_CONFIG_DIR='/etc/ddns-harden'
DDNS_CONFIG="$DDNS_CONFIG_DIR/config.json"

RED='31m'
GREEN='32m'
YELLOW='33m'
BLUE='36m'

SYSTEMCTL_CMD=$(command -v systemctl 2>/dev/null)
APT_UPDATED=0

# 以下三个是纯函数（不碰系统），release/harden_test.sh 源进本文件后直接测它们
# 把 ALLOW_PORTS 解析成 ufw 放行规则，每行一条 <端口或段>/<proto>；非法项返回 1 并指出是哪一项
parse_ports() {
  local spec="${1:-}" item portpart proto start end p emitted=0
  [[ -z "$spec" ]] && return 1
  local IFS=','
  for item in $spec; do
    item="${item// /}"
    [[ -z "$item" ]] && continue
    proto='both'
    portpart="$item"
    if [[ "$item" == */* ]]; then
      portpart="${item%/*}"
      proto="${item##*/}"
    fi
    case "$proto" in
    tcp | udp | both) ;;
    *)
      echo "ALLOW_PORTS 项 '$item' 的协议后缀只能是 tcp/udp/both" >&2
      return 1
      ;;
    esac
    if [[ "$portpart" == *-* ]]; then
      start="${portpart%-*}"
      end="${portpart#*-}"
      if ! [[ "$start" =~ ^[0-9]+$ && "$end" =~ ^[0-9]+$ ]]; then
        echo "ALLOW_PORTS 项 '$item' 的端口段不是数字" >&2
        return 1
      fi
      if ((start < 1 || start > 65535 || end < 1 || end > 65535 || start > end)); then
        echo "ALLOW_PORTS 项 '$item' 端口段越界或起>止" >&2
        return 1
      fi
      p="${start}:${end}"
    else
      if ! [[ "$portpart" =~ ^[0-9]+$ ]]; then
        echo "ALLOW_PORTS 项 '$item' 的端口不是数字" >&2
        return 1
      fi
      if ((portpart < 1 || portpart > 65535)); then
        echo "ALLOW_PORTS 项 '$item' 端口越界（1-65535）" >&2
        return 1
      fi
      p="$portpart"
    fi
    if [[ "$proto" == 'both' ]]; then
      echo "$p/tcp"
      echo "$p/udp"
    else
      echo "$p/$proto"
    fi
    emitted=1
  done
  # 一个有效项都没有（如全是逗号）按非法处理：调用方拿空规则去 default-deny 会断流
  ((emitted)) || return 1
  return 0
}

valid_port() { [[ "${1:-}" =~ ^[0-9]+$ ]] && (($1 >= 1 && $1 <= 65535)); }

valid_ip() {
  local ip="${1:-}" o
  if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    local IFS='.'
    for o in $ip; do ((o <= 255)) || return 1; done
    return 0
  fi
  [[ "$ip" == *:* && "$ip" =~ ^[0-9A-Fa-f:.]+$ ]] && return 0
  return 1
}

# 公钥能否被 sshd 接受：单独写临时文件用 ssh-keygen -lf 验指纹。验过才往 authorized_keys 写，
# 坏键不进文件（sshd 忽略坏行=关密码后锁死，且留下垃圾挡住后续校验）
pubkey_parseable() {
  local key="${1:-}" tmp rc
  [[ -z "$key" ]] && return 1
  tmp=$(mktemp) || return 1
  printf '%s\n' "$key" >"$tmp"
  ssh-keygen -lf "$tmp" >/dev/null 2>&1
  rc=$?
  rm -f "$tmp"
  return $rc
}

colorEcho() { echo -e "\033[${1}${@:2}\033[0m" 1>&2; }

# 给单个值上色（嵌进一行内），与 colorEcho 的整行色区分；颜色常量已带 m，这里不再补
cv() { printf '\033[%s%s\033[0m' "$1" "$2"; }
# 读数行：标签统一两个汉字（显示等宽），不用 printf 字节 padding（中文按字节补会错位）
srow() { printf '  %s  %s\n' "$1" "$2"; }

# 内核来源：XanMod/bbrplus/elrepo 这些第三方内核不在发行版安全更新覆盖内，读数里要标出来。
# 只按 uname -r 的特征串认，不去翻 apt 源——那既需要 root，也会被后续改源误导
kernel_origin() {
  case "${1:-}" in
  '' | unknown) echo '取不到' ;;
  *xanmod*) echo '第三方 xanmod' ;;
  *bbrplus*) echo '第三方 bbrplus' ;;
  *elrepo*) echo '第三方 elrepo' ;;
  *) echo '发行版' ;;
  esac
}

# ddns 的 console script 常被 pipx 装在 ~/.local/bin，而 root 的非交互/新 shell PATH 里通常没有这一项，
# 于是 `ddns` 报 command not found（定时器不靠它，它靠 python -m ddns，所以 timer 照跑）。这里把所有
# 常见安装位置都查一遍，返回第一个可执行路径；找不到返回 1。
ddns_resolve() {
  local p
  if p=$(command -v ddns 2>/dev/null) && [[ -n "$p" && -x "$p" ]]; then
    printf '%s\n' "$p"
    return 0
  fi
  for p in /usr/local/bin/ddns "$HOME/.local/bin/ddns" /root/.local/bin/ddns; do
    [[ -x "$p" ]] && { printf '%s\n' "$p"; return 0; }
  done
  return 1
}

# 节点 id 取自节点配置（不依赖 jq）；文件不存在/无该键返回空
node_id_from_config() {
  sed -n 's/.*"node_id"[[:space:]]*:[[:space:]]*\([0-9]\+\).*/\1/p' "${1:-/etc/vnet/config.json}" 2>/dev/null | head -n1
}

# self-update 覆盖目标：脚本以文件在跑就覆盖它自己；stdin（curl|bash -s）没有本地文件就装到默认路径
self_update_target() {
  local src="${1-${BASH_SOURCE[0]:-}}"
  if [[ -n "$src" && -f "$src" ]]; then
    realpath "$src" 2>/dev/null || echo "$src"
  else
    echo '/usr/local/bin/vnet-harden'
  fi
}

# 状态记在内存里再整文件重写，不用 sed 改单行（值里带特殊字符时 sed 会写坏）
declare -A STATE_KV
state_set() {
  STATE_KV["$1"]="$2"
  state_flush
}
state_flush() {
  local k
  : >"$STATE_FILE"
  for k in "${!STATE_KV[@]}"; do echo "$k=${STATE_KV[$k]}" >>"$STATE_FILE"; done
}
# 重跑时把上次的状态读回内存：否则 state_flush 只写本次的键，会把首次记的改前基线冲掉
state_load() {
  [[ -f "$STATE_FILE" ]] || return 0
  local line k v
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    k="${line%%=*}"
    v="${line#*=}"
    STATE_KV["$k"]="$v"
  done <"$STATE_FILE"
}

apt_install() {
  local pkg
  for pkg in "$@"; do
    dpkg -s "$pkg" >/dev/null 2>&1 && continue
    if ((APT_UPDATED == 0)); then
      apt-get -qq update || colorEcho ${YELLOW} "软件源刷新失败：发行版可能已进归档，先修 /etc/apt/sources.list。"
      APT_UPDATED=1
    fi
    if ! apt-get -y -qq install "$pkg" </dev/null; then
      colorEcho ${RED} "装 $pkg 失败（若是 404 多半是软件源过期，不是本脚本的问题）。"
      return 1
    fi
  done
  return 0
}

# sshd -T 倒的是生效配置（小写键）；有 Match 块时裸 -T 可能报错，补一个连接上下文再试
sshd_effective() {
  sshd -T 2>/dev/null || sshd -T -C user=root,host=localhost,addr=127.0.0.1 2>/dev/null
}

ssh_port() {
  local p
  p=$(sshd_effective | awk '/^port /{print $2; exit}')
  echo "${p:-22}"
}

# sshd 同名关键字只取第一个值：Include 在 sshd_config 里的位置决定 sshd_config.d 的读取顺序（按文件名排序），
# 主配置里 Include 之前写的 PasswordAuthentication 更靠前。打印第一个压制来源（值不是 no 的）file:line: 语句，找不到就空
ssh_pa_override() {
  local main="${1:-/etc/ssh/sshd_config}" dir="${2:-/etc/ssh/sshd_config.d}"
  local inc_line hit f
  inc_line=$(grep -nE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$main" 2>/dev/null | head -n1 | cut -d: -f1)
  if [[ -n "$inc_line" ]]; then
    hit=$(awk -v n="$inc_line" 'NR < n && tolower($1) == "passwordauthentication" && tolower($2) != "no" {print FILENAME":"NR": "$1" "$2; exit}' "$main" 2>/dev/null)
    [[ -n "$hit" ]] && { printf '%s\n' "$hit"; return 0; }
  fi
  while IFS= read -r f; do
    hit=$(awk 'tolower($1) == "passwordauthentication" && tolower($2) != "no" {print FILENAME":"NR": "$1" "$2; exit}' "$f" 2>/dev/null)
    [[ -n "$hit" ]] && { printf '%s\n' "$hit"; return 0; }
  done < <(find "$dir" -maxdepth 1 -type f -name '*.conf' ! -name '99-vnet-harden.conf' 2>/dev/null | LC_ALL=C sort)
  return 0
}

# 压制提示按来源分两种说法：主配置 Include 之前那行，还是 sshd_config.d 里文件名排序更靠前的文件；
# 修法按关键字注释整个文件里的 PasswordAuthentication，不按行号：配置前后增删几行、被重新生成过，
# 命令照样注到对的地方；# 后面留着原值，日后 grep 得到当时改的是什么。只打印不执行（别人的文件）
ssh_pa_hint() {
  local blocker="${1:-}" main="${2:-/etc/ssh/sshd_config}"
  local file
  file=${blocker%%:*}
  if [[ "$file" == "$main" ]]; then
    printf '压住它的是主配置（Include 之前那行 PasswordAuthentication 不是 no）：\n'
    printf 'sshd 只认第一个值，sshd_config.d 里怎么写都压不过。\n'
  else
    printf '压住它的是 sshd_config.d/%s：\n' "${file##*/}"
    printf '它按文件名排在 99-vnet-harden.conf 之前，先被读到，压住了 drop-in。\n'
  fi
  printf '手工修：先备份，再按关键字注释（不按行号，原值留在 # 后）：\n'
  printf 'f=%s\n' "$file"
  printf 'cp -a "$f"{,.$(date +%%F)}\n'
  printf "sed -i 's/^[[:space:]]*PasswordAuthentication/#&/' \"\$f\"\n"
  printf 'sshd -t && systemctl reload ssh，然后带 SSH_PUBKEY 重跑。\n'
  # cloud-init 会在重启时把 50-cloud-init.conf 写回来，光注释不够
  if [[ "${file##*/}" == '50-cloud-init.conf' ]]; then
    printf '这份文件由 cloud-init 生成，光注释不够：\n'
    printf '/etc/cloud/cloud.cfg.d/99-disable-password-auth.cfg\n'
    printf '里写 ssh_pwauth: false，否则重启会被改回来。\n'
  fi
}

# state 里存的是 file:line: 语句，行号只在跑的那会儿准；--status 只显示文件与语句，
# 配置改过之后不会拿旧行号指错地方。路径也缩成 sshd_config / sshd_config.d/ 开头
ssh_pa_label() {
  local b="${1:-}"
  [[ -z "$b" ]] && return 0
  printf '%s\n' "$b" | sed 's#^/etc/ssh/sshd_config\.d/#sshd_config.d/#; s#^/etc/ssh/sshd_config:#sshd_config:#; s#^\([^:]*\):[0-9]\+:[[:space:]]*#\1: #'
}

# SSH 白名单默认只 root（运维只用 root）；个别机器要用别的登录账号时设 SSH_ALLOW_USERS='root <名字>'。
# 被挡在外的现有登录账号会在 sec_ssh 里提示，不静默锁人
ssh_allow_users() {
  if [[ -n "${SSH_ALLOW_USERS:-}" ]]; then
    echo "$SSH_ALLOW_USERS"
    return 0
  fi
  echo 'root'
}

detect_distro() {
  DISTRO_ID=''
  DISTRO_VER=''
  DISTRO_CODENAME=''
  [[ -r /etc/os-release ]] && . /etc/os-release
  DISTRO_ID="${ID:-}"
  DISTRO_VER="${VERSION_ID:-}"
  DISTRO_CODENAME="${VERSION_CODENAME:-}"
}

eol_warn() {
  # Debian 11 的 LTS 已于 2026-08-31 结束，此后不再收安全补丁；自动补丁那条在 EOL 上是空转
  if [[ "$DISTRO_ID" == 'debian' && -n "$DISTRO_VER" ]] && ((${DISTRO_VER%%.*} < 12)); then
    colorEcho ${YELLOW} "这台是 Debian ${DISTRO_VER}，已过安全支持期：unattended-upgrades 装上也拿不到新补丁。先升 Debian 12/13 再谈加固，顺序不能反。"
  fi
}

default_iface() {
  ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

# 有半配置包时，之后每一笔 apt 事务都会先重试它、失败就整笔停下（grub-cloud-amd64 缺 /boot/efi 就是这样）。
# 只提示不动手：configure/purge 是别人的包，代按会把系统状态改得更难查。
precheck_dpkg() {
  local audit
  command -v dpkg >/dev/null 2>&1 || return 0
  audit=$(dpkg --audit 2>/dev/null) || return 0
  [[ -n "$audit" ]] || return 0
  colorEcho ${YELLOW} "dpkg 里有没配完的包，后面装 vnstat/fail2ban/ddns 都会被它一起卡住："
  printf '%s\n' "$audit" | sed 's/^/    /' >&2
  colorEcho ${YELLOW} "本脚本不代修包：先 dpkg --audit 看原因，dpkg --configure -a 重试配置；还不行就 apt-get -y purge 掉那个包，再重跑。"
}

#  best-effort 探 DHCP：networkd 的 .network 或 ifupdown 的 interfaces 里写了 DHCP 才算
detect_dhcp() {
  [[ "${DHCP:-}" == '1' ]] && return 0
  grep -rqiE '^\s*DHCP\s*=\s*(yes|ipv4|ipv6)' /etc/systemd/network/ 2>/dev/null && return 0
  grep -qiE '^\s*iface\s+\S+\s+inet\s+dhcp' /etc/network/interfaces /etc/network/interfaces.d/* 2>/dev/null && return 0
  return 1
}

####### 各段 #######

sec_base() {
  colorEcho ${BLUE} "== 基础：时区 + vnstat =="
  local before after iface
  before=$(timedatectl show -p Timezone --value 2>/dev/null)
  if [[ "$before" != 'Asia/Shanghai' ]]; then
    timedatectl set-timezone Asia/Shanghai 2>/dev/null
    after=$(timedatectl show -p Timezone --value 2>/dev/null)
    colorEcho ${GREEN} "时区：${before:-取不到} -> ${after:-设置失败}"
  else
    colorEcho ${GREEN} "时区已是 Asia/Shanghai，不动。"
  fi

  if apt_install vnstat; then
    systemctl enable --now vnstat >/dev/null 2>&1
    iface=$(default_iface)
    if [[ -n "$iface" ]]; then
      vnstat -i "$iface" --add >/dev/null 2>&1
      colorEcho ${GREEN} "vnstat 就绪，统计出网网卡 ${iface}（看流量：vnstat -d / vnstat -m）。"
    else
      colorEcho ${YELLOW} "vnstat 装好了但探不到默认出网网卡：跑 vnstat --iflist 看它统计的是不是你要的那张。"
    fi
  fi
}

sec_patch() {
  colorEcho ${BLUE} "== 自动安全补丁 + 条件重启 =="
  local reboot_time="${REBOOT_TIME:-$REBOOT_TIME_DEFAULT}"
  if ! apt_install unattended-upgrades needrestart; then
    colorEcho ${YELLOW} "自动补丁这步没装成，跳过（其余段照常）。"
    return 0
  fi
  mkdir -p /etc/needrestart/conf.d
  # 只自动装 security 源；有内核更新才重启，固定低峰窗口，三台靠 REBOOT_TIME 错开
  cat >"$UU_DROPIN" <<EOF
// 由 release/harden.sh 生成，--rollback 删除
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
Unattended-Upgrade::Allowed-Origins {
    "\${distro_id}:\${distro_codename}-security";
};
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "$reboot_time";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
EOF
  # needrestart 自动重启受库更新影响的服务，不弹交互菜单
  echo '$nrconf{restart} = '"'"'a'"'"';' >"$NEEDRESTART_DROPIN"
  systemctl enable --now apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1
  colorEcho ${GREEN} "自动安全补丁就绪：有内核更新才在 ${reboot_time} 重启（有人登录时不重启）。"
  if [[ "$DISTRO_ID" == 'debian' && -n "$DISTRO_VER" ]] && ((${DISTRO_VER%%.*} < 12)); then
    colorEcho ${YELLOW} "但本机是 EOL 发行版，security 源已不再供新补丁——这条现在是空转，先升系统。"
  fi
}

sec_logs() {
  colorEcho ${BLUE} "== journald 限额 =="
  mkdir -p /etc/systemd/journald.conf.d
  cat >"$JOURNAL_DROPIN" <<'EOF'
# 由 release/harden.sh 生成，--rollback 删除
[Journal]
SystemMaxUse=200M
SystemKeepFree=1G
MaxRetentionSec=2week
EOF
  systemctl restart systemd-journald 2>/dev/null
  colorEcho ${GREEN} "journald 上限 200M（保留至少 1G 空闲、最长 2 周），节点日志不会吃满小盘。"
}

sec_fail2ban() {
  colorEcho ${BLUE} "== fail2ban =="
  if ! apt_install fail2ban; then
    colorEcho ${YELLOW} "fail2ban 没装成，跳过。"
    return 0
  fi
  local backend='systemd' port
  # Debian 12 精简安装没有 /var/log/auth.log，sshd 日志走 journald；有 auth.log 才用文件后端
  [[ -f /var/log/auth.log ]] && backend='auto'
  port=$(ssh_port)
  mkdir -p /etc/fail2ban/jail.d
  cat >"$F2B_DROPIN" <<EOF
# 由 release/harden.sh 生成，--rollback 删除
[sshd]
enabled = true
backend = $backend
port = $port
maxretry = 5
findtime = 10m
bantime = 1h
bantime.increment = true
bantime.factor = 2
bantime.maxtime = 1w

[recidive]
enabled = true
logpath = /var/log/fail2ban.log
bantime = 1w
findtime = 1d
maxretry = 5
EOF
  systemctl enable --now fail2ban >/dev/null 2>&1
  systemctl restart fail2ban 2>/dev/null
  sleep 2
  if fail2ban-client status sshd >/dev/null 2>&1; then
    colorEcho ${GREEN} "fail2ban 就绪（sshd jail，backend=${backend}，递增封禁 + recidive 惯犯 jail）。"
  else
    colorEcho ${YELLOW} "fail2ban 装了但 sshd jail 没起来：看 systemctl status fail2ban 与 journalctl -u fail2ban（banaction 与 ufw 的共存要在真机确认）。"
  fi
}

sec_ssh() {
  colorEcho ${BLUE} "== SSH 密钥化 =="
  # 没写 drop-in 的原因记进 state.env：--status 才能分开说「没给公钥」「公钥不对」「写了没生效」
  if [[ -z "${SSH_PUBKEY:-}" ]]; then
    colorEcho ${YELLOW} "没给 SSH_PUBKEY，跳过 SSH 加固（不关密码登录）。要关：在运维机生成密钥对，把公钥经 SSH_PUBKEY 传进来重跑。"
    [[ -f "$SSH_DROPIN" ]] || state_set SSH_DROPIN_REMOVED no_pubkey
    return 0
  fi
  # 公钥形状 loose 校验：类型 + base64  blob，挡掉把私钥或乱串当公钥传进来
  if ! [[ "$SSH_PUBKEY" =~ ^(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)[[:space:]]+[A-Za-z0-9+/=]+ ]]; then
    colorEcho ${RED} "SSH_PUBKEY 不像公钥（应形如 'ssh-ed25519 AAAA… comment'）：不写、不关密码登录。"
    state_set SSH_DROPIN_REMOVED bad_pubkey
    return 1
  fi

  # 先验候选公钥本身，验过才写：坏键不进 authorized_keys
  if ! pubkey_parseable "$SSH_PUBKEY"; then
    colorEcho ${RED} "SSH_PUBKEY 解析不了（常见是把示例里的占位省略号当真钥传了）：不写、不关密码登录。"
    state_set SSH_DROPIN_REMOVED bad_pubkey
    return 1
  fi
  local ak='/root/.ssh/authorized_keys'
  mkdir -p /root/.ssh
  chmod 700 /root/.ssh
  touch "$ak"
  chmod 600 "$ak"
  if grep -qF "$SSH_PUBKEY" "$ak"; then
    colorEcho ${GREEN} "公钥已在 authorized_keys，不重复写。"
  else
    echo "$SSH_PUBKEY" >>"$ak"
    colorEcho ${GREEN} "公钥已写入 authorized_keys。"
  fi

  local before_pa before_rl
  before_pa=$(sshd_effective | awk '/^passwordauthentication /{print $2; exit}')
  before_rl=$(sshd_effective | awk '/^permitrootlogin /{print $2; exit}')

  mkdir -p /etc/ssh/sshd_config.d
  local allow_users
  allow_users=$(ssh_allow_users)
  # 提示被白名单挡在 SSH 外的现有登录账号（云镜像默认用户如 admin），知情而非静默锁人
  local others u
  others=''
  while IFS= read -r u; do
    [[ -n "$u" && " $allow_users " != *" $u "* ]] && others+=" $u"
  done < <(awk -F: '$3>=1000 && $7 !~ /(nologin|false)$/ {print $1}' /etc/passwd 2>/dev/null)
  if [[ -n "$others" ]]; then
    colorEcho ${YELLOW} "这些登录账号将被 AllowUsers 挡在 SSH 外：${others# }（不用就忽略；要用设 SSH_ALLOW_USERS='root ${others# }' 重跑）。"
  fi
  cat >"$SSH_DROPIN" <<EOF
# 由 release/harden.sh 生成，--rollback 删除
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
MaxAuthTries 3
MaxStartups 5:30:20
LoginGraceTime 20
ClientAliveInterval 60
ClientAliveCountMax 3
X11Forwarding no
AllowAgentForwarding no
AllowUsers $allow_users
EOF
  if ! sshd -t 2>/dev/null; then
    colorEcho ${RED} "sshd 配置校验不过，删掉 drop-in、不 reload。"
    state_set SSH_DROPIN_REMOVED sshd_test_failed
    rm -f "$SSH_DROPIN"
    return 1
  fi
  # 断言 drop-in 真被 Include 进生效配置：Debian 主配置顶部有 Include 才生效，否则等于没写
  local eff
  eff=$(sshd_effective | awk '/^passwordauthentication /{print $2; exit}')
  if [[ "$eff" != 'no' ]]; then
    if ! grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config 2>/dev/null; then
      mkdir -p "$STATE_DIR/backup"
      [[ -f "$STATE_DIR/backup/sshd_config" ]] || cp -a /etc/ssh/sshd_config "$STATE_DIR/backup/sshd_config"
      sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
      state_set SSHD_INCLUDE_ADDED 1
    fi
    eff=$(sshd_effective | awk '/^passwordauthentication /{print $2; exit}')
    if [[ "$eff" != 'no' ]]; then
      # sshd 只认第一个值：指出到底是哪个文件哪一行压住了 drop-in，用户才知道去改哪里
      local blocker
      blocker=$(ssh_pa_override)
      if [[ -n "$blocker" ]]; then
        colorEcho ${RED} "drop-in 没进生效配置（sshd -T 仍是 ${eff:-取不到}）：更靠前的一行压住了它 —— ${blocker}"
        local h hint
        hint=$(ssh_pa_hint "$blocker")
        while IFS= read -r h; do colorEcho ${YELLOW} "$h"; done <<<"$hint"
        state_set SSH_DROPIN_BLOCKER "$blocker"
        state_set SSH_DROPIN_REMOVED pa_not_effective
      else
        colorEcho ${RED} "drop-in 没进生效配置（sshd -T 仍是 ${eff:-取不到}）：没找到别的 PasswordAuthentication 行，查 Include 与 /etc/ssh/sshd_config.d 权限。"
        state_set SSH_DROPIN_REMOVED pa_not_effective
      fi
      colorEcho ${RED} "删掉 drop-in、不关密码登录。"
      rm -f "$SSH_DROPIN"
      return 1
    fi
  fi
  systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null
  # 这次成了：清掉上一次失败留下的原因，免得 --status 还报旧的
  unset 'STATE_KV[SSH_DROPIN_REMOVED]' 'STATE_KV[SSH_DROPIN_BLOCKER]'
  state_set SSH_HARDENED 1
  colorEcho ${GREEN} "SSH：passwordauthentication ${before_pa:-取不到} -> no，permitrootlogin ${before_rl:-取不到} -> prohibit-password（只留密钥）；AllowUsers=${allow_users}。"
}

sec_firewall() {
  colorEcho ${BLUE} "== 防火墙（ufw default-deny）=="
  local missing=''
  [[ -z "${ALLOW_PORTS:-}" ]] && missing+='ALLOW_PORTS '
  [[ -z "${PUSH_PORT:-}" ]] && missing+='PUSH_PORT '
  [[ -z "${PANEL_IP:-}" ]] && missing+='PANEL_IP '
  if [[ -n "$missing" ]]; then
    colorEcho ${YELLOW} "防火墙跳过：缺 ${missing}（default-deny 必须先把业务口与管理口放行，否则节点会断）。给齐这三个变量重跑即可单独补这一段。"
    return 0
  fi
  if ! valid_ip "$PANEL_IP"; then
    colorEcho ${RED} "PANEL_IP '$PANEL_IP' 不是合法 IP：不做防火墙。"
    return 1
  fi
  if ! valid_port "$PUSH_PORT"; then
    colorEcho ${RED} "PUSH_PORT '$PUSH_PORT' 不是合法端口：不做防火墙。"
    return 1
  fi
  local rules
  if ! rules=$(parse_ports "$ALLOW_PORTS"); then
    colorEcho ${RED} "ALLOW_PORTS 解析失败（上面指出了哪一项）：不做防火墙。"
    return 1
  fi
  # 全是分隔符（如 ','）会解析出空规则：default-deny 下等于断掉全部业务口，必须挡
  if [[ -z "$rules" ]]; then
    colorEcho ${RED} "ALLOW_PORTS 没解析出任何端口：不做防火墙。"
    return 1
  fi
  if ! apt_install ufw; then
    colorEcho ${YELLOW} "ufw 没装成，跳过防火墙。"
    return 0
  fi

  # 改前基线只在首次记：重跑时 ufw 已是 active/deny，再记一次会把回滚基线污染成「改前就开着」
  local pre_active pre_default
  if [[ -z "${STATE_KV[PRE_UFW_ACTIVE]:-}" ]]; then
    pre_active=$(ufw status 2>/dev/null | awk '/^Status:/{print $2; exit}')
    pre_default=$(ufw status verbose 2>/dev/null | awk -F'[ (]' '/^Default:/{print $2; exit}')
    state_set PRE_UFW_ACTIVE "${pre_active:-absent}"
    state_set PRE_UFW_DEFAULT_IN "${pre_default:-deny}"
  fi
  : >"$UFW_RULES_FILE"

  local sshp rule
  sshp=$(ssh_port)
  # 顺序是硬要求：先放 SSH，再放业务与管理口，最后才 default deny + enable。
  # 任一条放行失败就中止（不 enable）：default-deny 下漏放 SSH 会锁死、漏放业务口会断流
  ufw_allow "allow $sshp/tcp" || {
    colorEcho ${RED} "SSH 口放行失败，不启用防火墙。"
    return 1
  }
  while IFS= read -r rule; do
    [[ -z "$rule" ]] && continue
    ufw_allow "allow $rule" || {
      colorEcho ${RED} "业务口 $rule 放行失败，不启用防火墙。"
      return 1
    }
  done <<<"$rules"
  ufw_allow "allow from $PANEL_IP to any port $PUSH_PORT proto tcp" || {
    colorEcho ${RED} "管理口放行失败，不启用防火墙。"
    return 1
  }
  if detect_dhcp; then
    ufw_allow "allow proto udp from any port 67 to any port 68"
  else
    colorEcho ${BLUE} "没探到 DHCP（静态配置）：不放行 UDP 67/68；若本机其实走 DHCP 续租，加 DHCP=1 重跑。"
  fi

  ufw default deny incoming >/dev/null 2>&1
  ufw default allow outgoing >/dev/null 2>&1
  ufw --force enable >/dev/null 2>&1
  state_set UFW_ENABLED 1
  colorEcho ${GREEN} "ufw 已启用：default deny incoming，放行 SSH(${sshp}) + 业务口 + 管理口(仅 ${PANEL_IP})。"
  ufw status verbose 2>/dev/null | sed 's/^/    /' >&2
}

# 加一条 ufw 规则并记进清单（--rollback 按清单逐条删）；ufw 对已存在的规则会跳过，天然幂等。
# spec 故意不加引号：ufw 要的是分开的词，入参都已校验过（IP/端口/解析后的规则），无注入面
ufw_allow() {
  local spec="$1"
  echo "$spec" >>"$UFW_RULES_FILE"
  ufw $spec >/dev/null 2>&1
}

# 只读断言：Debian 12 默认开 AppArmor，被内核参数关掉就提示（启用要改 cmdline+重启，不代按）
check_apparmor() {
  local enabled='no'
  if command -v aa-status >/dev/null 2>&1 && aa-status --enabled >/dev/null 2>&1; then
    enabled='yes'
  elif [[ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" == 'Y' ]]; then
    enabled='yes'
  fi
  if [[ "$enabled" == 'yes' ]]; then
    colorEcho ${GREEN} "AppArmor 已启用。"
  else
    colorEcho ${YELLOW} "AppArmor 没启用（Debian 12 默认开）：查内核 cmdline 是否带 apparmor=0 / security=；启用要改 cmdline 并重启，本脚本不代按。"
  fi
}

####### 死人开关 / 确认 / 回滚 / 读数 #######

write_revert_helper() {
  mkdir -p "$STATE_DIR"
  cat >"$REVERT_HELPER" <<'EOF'
#!/bin/bash
# 由 harden.sh 生成：10 分钟内未跑 --confirm 时自动退回，保证还能登录
rm -f /etc/ssh/sshd_config.d/99-vnet-harden.conf
if sshd -t 2>/dev/null; then systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; fi
ufw --force disable 2>/dev/null
logger -t vnet-harden "自动还原已触发：删除 sshd drop-in、关闭 ufw（10 分钟内未确认）"
EOF
  chmod 700 "$REVERT_HELPER"
}

# 是否起锁死保险：真改了 ssh 认证或开了防火墙，且没开自动确认
should_arm_revert() {
  [[ "${AUTO_CONFIRM:-0}" == '1' ]] && return 1
  [[ "${STATE_KV[SSH_HARDENED]:-0}" == '1' || "${STATE_KV[UFW_ENABLED]:-0}" == '1' ]]
}

arm_revert() {
  # 自动确认：跑完即生效、不起保险（操作者已验过登录或自负锁死风险）
  if [[ "${AUTO_CONFIRM:-0}" == '1' ]]; then
    do_confirm
    colorEcho ${GREEN} "AUTO_CONFIRM=1：跑完即确认，不起 10 分钟自动还原保险；要退回用 --rollback。"
    return 0
  fi
  should_arm_revert || return 0
  write_revert_helper
  systemctl stop "$REVERT_UNIT.timer" >/dev/null 2>&1
  systemctl stop "$REVERT_UNIT.service" >/dev/null 2>&1
  systemd-run --on-active=10m --unit="$REVERT_UNIT.service" --description='VNet harden auto-revert' \
    /bin/bash "$REVERT_HELPER" >/dev/null 2>&1
  colorEcho ${YELLOW} "已起 10 分钟自动还原保险。现在请开一个【新】SSH 会话确认能登录，然后跑：harden.sh --confirm"
  colorEcho ${YELLOW} "  10 分钟内不确认会自动退回（删 sshd drop-in + 关 ufw）；确认登不上就等它自动还原，别 reboot。"
}

do_confirm() {
  systemctl stop "$REVERT_UNIT.timer" >/dev/null 2>&1
  systemctl stop "$REVERT_UNIT.service" >/dev/null 2>&1
  systemctl reset-failed "$REVERT_UNIT.service" >/dev/null 2>&1
  rm -f "$REVERT_HELPER"
  colorEcho ${GREEN} "已确认：自动还原保险已取消，加固保留。"
}

do_rollback() {
  local had_state=0
  if [[ -f "$STATE_FILE" ]]; then
    . "$STATE_FILE"
    had_state=1
  fi
  systemctl stop "$REVERT_UNIT.timer" >/dev/null 2>&1
  systemctl stop "$REVERT_UNIT.service" >/dev/null 2>&1
  systemctl reset-failed "$REVERT_UNIT.service" >/dev/null 2>&1

  # ufw：只在有本脚本的运行记录时才动它——没记录就 reset 会 wipe 掉别人预先存的规则
  if ((had_state)) && command -v ufw >/dev/null 2>&1; then
    if [[ "${PRE_UFW_ACTIVE:-absent}" == 'absent' ]]; then
      ufw --force reset >/dev/null 2>&1
      ufw --force disable >/dev/null 2>&1
    else
      if [[ -f "$UFW_RULES_FILE" ]]; then
        local spec
        while IFS= read -r spec; do
          [[ -z "$spec" ]] && continue
          ufw --force delete $spec >/dev/null 2>&1
        done <"$UFW_RULES_FILE"
      fi
      ufw default "${PRE_UFW_DEFAULT_IN:-deny}" incoming >/dev/null 2>&1
      [[ "${PRE_UFW_ACTIVE}" == 'inactive' ]] && ufw --force disable >/dev/null 2>&1
    fi
  fi

  # sshd：删 drop-in 即回到改前的生效配置；补过 Include 的从备份还原主配置
  rm -f "$SSH_DROPIN"
  if [[ "${SSHD_INCLUDE_ADDED:-0}" == '1' && -f "$STATE_DIR/backup/sshd_config" ]]; then
    cp -a "$STATE_DIR/backup/sshd_config" /etc/ssh/sshd_config
  fi
  if sshd -t 2>/dev/null; then systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; fi

  rm -f "$JOURNAL_DROPIN"
  systemctl restart systemd-journald 2>/dev/null
  rm -f "$F2B_DROPIN"
  systemctl restart fail2ban 2>/dev/null
  rm -f "$UU_DROPIN" "$NEEDRESTART_DROPIN"
  rm -f "$REVERT_HELPER"
  rm -rf "$STATE_DIR"

  # ddns：删本脚本写进 /etc/ddns-harden 的配置、ddns 装的定时任务与缓存；不卸载 ddns 本体
  rm -rf "$DDNS_CONFIG_DIR"
  local ddns_bin
  ddns_bin=$(command -v ddns 2>/dev/null || true)
  [[ -z "$ddns_bin" ]] && ddns_bin=$(ddns_resolve 2>/dev/null || true)
  [[ -n "$ddns_bin" ]] && "$ddns_bin" task --uninstall >/dev/null 2>&1
  # ddns 卸载不了（不在 PATH）时，按单元里的配置路径认领后自己删，别留个指向已删配置的定时器
  if [[ -f /etc/systemd/system/ddns.service ]] && grep -qF "$DDNS_CONFIG" /etc/systemd/system/ddns.service 2>/dev/null; then
    systemctl disable --now ddns.timer >/dev/null 2>&1
    rm -f /etc/systemd/system/ddns.service /etc/systemd/system/ddns.timer
    systemctl daemon-reload >/dev/null 2>&1
  fi
  rm -f /tmp/ddns.*.cache 2>/dev/null
  colorEcho ${GREEN} "已删 ddns 配置、定时任务与缓存（ddns 本体保留）。"
  colorEcho ${GREEN} "已删除本脚本写的配置并还原 ufw/sshd。"
  colorEcho ${YELLOW} "包仍装着（vnstat/fail2ban/ufw/unattended-upgrades/needrestart），要彻底退就 apt remove；时区改回用 timedatectl set-timezone Etc/UTC。"
}

# ddns.newfuture.cc 续租：先看四个 DDNS_* 参数，缺一个就整段跳过（连包都不装，节点不留用不上的东西）
# -> 装包 -> 用注入的参数生成最简配置 -> 按这份配置真跑一次更新做自检 -> 自检过了才装定时任务。
# 凭据只从运行环境/secrets 注入（文件头的 DDNS_* 变量），不写进脚本、不回显；任一步失败就停在那一步，不带着
# 半套配置去续租。回滚见 do_rollback：删本脚本写的配置、定时任务与缓存，不卸载 ddns 本体。

sec_ddns() {
  colorEcho ${BLUE} "== DDNS 配置 =="

  # 四个参数缺一个就整段跳过：连 ddns 都不装——节点上不该留一个用不上的包和一份空配置
  local missing=''
  [[ -z "${DDNS_DNS:-}" ]] && missing+=' DDNS_DNS'
  [[ -z "${DDNS_ID:-}" ]] && missing+=' DDNS_ID'
  [[ -z "${DDNS_TOKEN:-}" ]] && missing+=' DDNS_TOKEN'
  [[ -z "${DDNS_IPV4:-}" ]] && missing+=' DDNS_IPV4'
  if [[ -n "$missing" ]]; then
    colorEcho ${YELLOW} "缺${missing}（环境变量或 secrets 注入）：整段跳过，不装 ddns、不写配置、不装定时任务。"
    # 这次跳过不会停掉以前装的续租：旧配置 + 旧 timer 还在跑，得告诉运维怎么停
    if [[ -f "$DDNS_CONFIG" || -f /etc/systemd/system/ddns.timer ]]; then
      colorEcho ${YELLOW} "注意：本机还留着之前装的 ddns 续租（配置 + 定时任务），仍在按旧配置跑。"
      colorEcho ${YELLOW} "要停掉跑 harden.sh --rollback（删配置与 timer，不卸包）。"
    fi
    # 之前装过 ddns 但 console script 不在 PATH 时，顺手把可执行文件链到 /usr/local/bin，
    # 这样手动 `ddns task --status` 才能跑起来（不装新包、不改配置）
    local _ddns_bin
    _ddns_bin=$(ddns_resolve 2>/dev/null) || true
    if [[ -n "${_ddns_bin:-}" && "$_ddns_bin" != /usr/local/bin/ddns ]]; then
      ln -sf "$_ddns_bin" /usr/local/bin/ddns 2>/dev/null || true
      command -v ddns >/dev/null 2>&1 && colorEcho ${GREEN} "ddns 已链到 /usr/local/bin，现在可直接跑 ddns task --status。"
    fi
    return 0
  fi

  # 先在常见位置找一遍：新 shell 的 PATH 可能没带 ~/.local/bin，装好的 ddns 也会被误判成没装
  if ! ddns_resolve >/dev/null 2>&1; then
    if ! apt_install pipx; then
      colorEcho ${YELLOW} "pipx 装不上（apt 源/网络），跳过 ddns，其余段照常。"
      return 0
    fi
    # pipx 对已安装的包返回非 0：先装，装不上再试 upgrade（覆盖「装过但这次 command -v 找不到」的重跑）
    if ! pipx install ddns >/dev/null 2>&1 && ! pipx upgrade ddns >/dev/null 2>&1; then
      colorEcho ${YELLOW} "pipx install/upgrade ddns 失败（看 pypi 通不通），跳过续租。"
      return 0
    fi
  fi
  # 把 console script 链到 /usr/local/bin：它是默认 PATH 的一部分，所有 shell 与 systemd 都能找到，
  # 不再依赖 ~/.local/bin 是否在 PATH 里（pipx ensurepath 只改 rc 文件，非交互 shell 读不到）
  local _ddns_bin
  _ddns_bin=$(ddns_resolve 2>/dev/null) || true
  if [[ -n "${_ddns_bin:-}" && "$_ddns_bin" != /usr/local/bin/ddns ]]; then
    ln -sf "$_ddns_bin" /usr/local/bin/ddns 2>/dev/null || true
  fi
  # 当前进程 PATH 也保证带上，避免本脚本后续调用落空
  if ! command -v ddns >/dev/null 2>&1; then PATH="/usr/local/bin:$PATH"; fi
  if ! command -v ddns >/dev/null 2>&1; then
    colorEcho ${YELLOW} "ddns 装完仍不在 PATH（pipx 默认 $HOME/.local/bin），跳过续租。"
    return 0
  fi
  colorEcho ${GREEN} "ddns 就绪：$(ddns --version 2>/dev/null | head -n1)"

  if [[ ! "$DDNS_DNS" =~ ^[a-z0-9_]+$ ]]; then
    colorEcho ${RED} "DDNS_DNS 要写 ddns 的提供方名（如 dnspod），不是要更新的域名：不写配置。"
    return 0
  fi
  # id/token 只放行这些字符：够各提供方用，也保证拼出来就是合法 JSON（不在 bash 里做转义）
  if [[ ! "$DDNS_ID" =~ ^[A-Za-z0-9._~+/=-]+$ || ! "$DDNS_TOKEN" =~ ^[A-Za-z0-9._~+/=,-]+$ ]]; then
    colorEcho ${RED} "DDNS_ID/DDNS_TOKEN 含不支持的字符（只收字母数字和 ._~+/=,-）：不写配置。"
    return 0
  fi

  # ipv4 是要更新的域名（逗号分隔），IP 由 ddns 自己从公网接口取；域名先过一遍字符集，别往 JSON 里塞脏值
  local domains='' one IFS=','
  for one in ${DDNS_IPV4}; do
    one=$(printf '%s' "$one" | tr -d '[:space:]')
    [[ -z "$one" ]] && continue
    if [[ ! "$one" =~ ^[A-Za-z0-9*_.-]+$ ]]; then
      colorEcho ${RED} "DDNS_IPV4 里的 '${one}' 不像域名：不写配置。"
      return 0
    fi
    domains+="${domains:+, }\"${one}\""
  done
  if [[ -z "$domains" ]]; then
    colorEcho ${YELLOW} "DDNS_IPV4 里没有有效域名：不写配置。"
    return 0
  fi

  # 只写本脚本管的四个字段；目录 700、文件 600，token 不进任何输出
  if ! mkdir -p "$DDNS_CONFIG_DIR"; then
    colorEcho ${RED} "建不了 ${DDNS_CONFIG_DIR}：不写配置。"
    return 0
  fi
  chmod 700 "$DDNS_CONFIG_DIR" 2>/dev/null  # 目录/文件只给 root；chmod 不支持的文件系统上不因此中断
  local before='无'
  [[ -f "$DDNS_CONFIG" ]] && before=$(sed -n 's/.*"ipv4".*\[\(.*\)\].*/\1/p' "$DDNS_CONFIG" | tr -d '"')
  local tmp
  tmp=$(mktemp "$DDNS_CONFIG_DIR/.config.XXXXXX") || return 0
  cat >"$tmp" <<EOF
{
  "dns": "${DDNS_DNS}",
  "id": "${DDNS_ID}",
  "token": "${DDNS_TOKEN}",
  "ipv4": [${domains}]
}
EOF
  chmod 600 "$tmp" 2>/dev/null
  mv -f "$tmp" "$DDNS_CONFIG"
  colorEcho ${GREEN} "ddns 配置已写：${DDNS_CONFIG}（ipv4 域名：${before:-无} -> ${DDNS_IPV4}）"

  # 自检：按这份配置真跑一次更新（debug 日志），过了再装任务，免得装个永远失败的定时器。
  # 失败不贴 ddns 的输出——debug 日志会带凭据，排障让运维自己跑同一条命令看。
  if ddns --debug --config "$DDNS_CONFIG" >/dev/null 2>&1; then
    colorEcho ${GREEN} "ddns 自检通过（配置/联网/凭据都跑通，记录已按配置更新一次）。"
  else
    colorEcho ${YELLOW} "ddns 自检没过（凭据/网络/提供方）：不装定时任务；看原因跑：ddns --debug --config ${DDNS_CONFIG}"
    return 0
  fi

  # --config 必须一起给：它会写进 systemd 单元的 ExecStart，定时任务才读得到这份配置
  if ddns task --install --config "$DDNS_CONFIG" >/dev/null 2>&1; then
    colorEcho ${GREEN} "ddns 定时续租已装好（默认 5 分钟一次；要改间隔用 task --install <分钟>）。"
  else
    colorEcho ${YELLOW} "ddns 定时任务没装上：配置留着，可手动跑 ddns task --install --config ${DDNS_CONFIG}"
    return 0
  fi
  local task_state
  task_state=$(ddns task --status 2>/dev/null | sed -n 's/^[[:space:]]*\(Installed\|Enabled\):[[:space:]]*/\1=/p' | tr '\n' ' ')
  colorEcho ${BLUE} "任务读数：${task_state:-取不到}"
}

do_status() {
  detect_distro
  printf '%s\n' "$(cv "$BLUE" '== 节点加固读数 ==')"

  local sysline="${DISTRO_ID:-?} ${DISTRO_VER:-?} (${DISTRO_CODENAME:-?})"
  if [[ "$DISTRO_ID" == 'debian' && -n "$DISTRO_VER" ]] && ((${DISTRO_VER%%.*} < 12)); then
    sysline+="  $(cv "$RED" '！EOL 无安全补丁，先升 12/13')"
  fi
  srow 系统 "$sysline"

  local krel korig kcol
  krel=$(uname -r 2>/dev/null)
  korig=$(kernel_origin "$krel")
  case "$korig" in
  发行版) kcol=$(cv "$GREEN" "$korig") ;;
  取不到) kcol=$(cv "$YELLOW" "$korig") ;;
  *) kcol=$(cv "$YELLOW" "$korig（需自维护安全更新）") ;;
  esac
  srow 内核 "${krel:-取不到}  $kcol"

  if [[ -n "$SYSTEMCTL_CMD" ]]; then
    local vact vver vcol
    vact=$(systemctl is-active vnet 2>/dev/null)
    vver=$(/usr/bin/vnet/vnet --version 2>/dev/null | head -n1 | cut -d' ' -f2)
    [[ "$vact" == 'active' ]] && vcol=$(cv "$GREEN" "$vact") || vcol=$(cv "$YELLOW" "${vact:-未知}")
    srow 节点 "$vcol"
    srow 版本 "${vver:-—（未安装 vnet）}"
    local pid
    pid=$(systemctl show -p MainPID --value vnet 2>/dev/null)
    if [[ "$pid" =~ ^[0-9]+$ ]] && ((pid > 0)); then
      srow 上限 "$(awk '/Max open files/{print $4"/"$5}' /proc/$pid/limits 2>/dev/null)"
    fi
  fi
  local nid
  nid=$(node_id_from_config)
  srow 编号 "${nid:-—（无 /etc/vnet/config.json）}"

  local cc qd ccol
  cc=$(sysctl -qn net.ipv4.tcp_congestion_control 2>/dev/null)
  qd=$(sysctl -qn net.core.default_qdisc 2>/dev/null)
  case "$cc" in bbr*) ccol=$(cv "$GREEN" "$cc") ;; *) ccol=$(cv "$YELLOW" "${cc:-取不到}") ;; esac
  srow 拥塞 "$ccol  qdisc=${qd:-取不到}"

  local tz ntp ncol
  tz=$(timedatectl show -p Timezone --value 2>/dev/null)
  ntp=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
  [[ "$ntp" == 'yes' ]] && ncol=$(cv "$GREEN" yes) || ncol=$(cv "$YELLOW" "${ntp:-no}")
  srow 时区 "${tz:-取不到}  NTP=$ncol"

  if command -v vnstat >/dev/null 2>&1; then
    local vn
    vn=$(vnstat --oneline 2>/dev/null | awk -F';' 'NF>=6{printf "今日 rx %s / tx %s（%s）", $4, $5, $2}')
    srow 流量 "${vn:-$(vnstat --oneline 2>/dev/null)}"
  fi

  if command -v fail2ban-client >/dev/null 2>&1; then
    local ips n
    if fail2ban-client status sshd >/dev/null 2>&1; then
      ips=$(fail2ban-client get sshd banip 2>/dev/null | tr '\n' ' ')
      n=$(fail2ban-client get sshd banip 2>/dev/null | wc -w)
      srow 封禁 "$(cv "$GREEN" "sshd 在封 ${n}")${ips:+  [${ips% }]}"
    else
      srow 封禁 "$(cv "$YELLOW" 'sshd jail 没起来')"
    fi
  fi

  if command -v ufw >/dev/null 2>&1; then
    local ust ucol
    ust=$(ufw status 2>/dev/null | awk '/^Status:/{print $2; exit}')
    [[ "$ust" == 'active' ]] && ucol=$(cv "$GREEN" active) || ucol=$(cv "$YELLOW" "${ust:-未装}")
    srow 防火 "$ucol"
  fi

  local pa rl pac rlc note='' note2=''
  pa=$(sshd_effective | awk '/^passwordauthentication /{print $2; exit}')
  rl=$(sshd_effective | awk '/^permitrootlogin /{print $2; exit}')
  [[ "$pa" == 'no' ]] && pac=$(cv "$GREEN" no) || pac=$(cv "$YELLOW" "${pa:-?}")
  # sshd -T 在新版会把 prohibit-password 倒成 without-password：两种是同一个值，统一显示成我们写的那个，
  # 免得读数看着像没设对
  case "$rl" in
  without-password | prohibit-password) rlc=$(cv "$GREEN" prohibit-password) ;;
  *) rlc=$(cv "$YELLOW" "${rl:-?}") ;;
  esac
  # 没写 drop-in 的原因由 sec_ssh 记进 state.env：这里按原因分开说，别把「写了没生效」也说成「没给公钥」。
  # 原因单独一行：带路径塞进认证行会到 200 列，终端硬折行后续行从第 0 列起，读数表就散了
  if [[ ! -f "$SSH_DROPIN" ]]; then
    state_load
    case "${STATE_KV[SSH_DROPIN_REMOVED]:-}" in
    no_pubkey) note='drop-in 未写：跑的时候没给 SSH_PUBKEY（带上重跑）' ;;
    bad_pubkey) note='drop-in 未写：SSH_PUBKEY 不是合法公钥（看跑的时候的红字）' ;;
    sshd_test_failed) note='drop-in 未写：写了但 sshd -t 不过，已删（看跑的时候的红字）' ;;
    pa_not_effective)
      note='drop-in 未写：生效的 PasswordAuthentication 不是 no，已删'
      # 压制来源只留相对路径并去掉行号：整条绝对路径会顶过 100 列，旧行号在配置改过后会指错地方
      [[ -n "${STATE_KV[SSH_DROPIN_BLOCKER]:-}" ]] && note2=$(ssh_pa_label "${STATE_KV[SSH_DROPIN_BLOCKER]}")
      ;;
    *)
      if [[ "${STATE_KV[SSH_HARDENED]:-0}" == '1' ]]; then
        note='drop-in 未写：加固后被删，带 SSH_PUBKEY 重跑重建'
      else
        note='drop-in 未写：多半跑的时候没给 SSH_PUBKEY'
      fi
      ;;
    esac
  fi
  srow 认证 "密码=$pac  root=$rlc"
  [[ -n "$note" ]] && srow 加固 "$(cv "$YELLOW" "$note")"
  [[ -n "$note2" ]] && srow 压制 "$(cv "$YELLOW" "$note2")"

  local dpct dcol dline
  dline=$(df -h / 2>/dev/null | awk 'NR==2{print $3" / "$2" ("$5")"}')
  dpct=$(df / 2>/dev/null | awk 'NR==2{gsub(/%/,"",$5);print $5}')
  if [[ "$dpct" =~ ^[0-9]+$ ]]; then
    if ((dpct >= 90)); then dcol=$(cv "$RED" "$dline")
    elif ((dpct >= 80)); then dcol=$(cv "$YELLOW" "$dline")
    else dcol=$(cv "$GREEN" "$dline"); fi
  else dcol="$dline"; fi
  srow 磁盘 "$dcol"

  if [[ -f /var/run/reboot-required ]]; then
    srow 重启 "$(cv "$YELLOW" '有（/var/run/reboot-required）')"
  else
    srow 重启 "$(cv "$GREEN" 无)"
  fi

  if systemctl list-timers "$REVERT_UNIT.timer" 2>/dev/null | grep -q "$REVERT_UNIT"; then
    srow 保险 "$(cv "$YELLOW" '计时中：确认能登录后 --confirm')"
  else
    srow 保险 "$(cv "$GREEN" '已取消/未起')"
  fi
}

# 只升 harden 脚本自身（不碰节点/配置；升 vnet 二进制走 upgrade.sh）。
# 下载失败或语法不过不覆盖，旧版继续可用；mv 换 inode 不影响正在跑的进程
do_self_update() {
  local target tmp remote_ver
  target=$(self_update_target)
  tmp=$(mktemp) || return 1
  if ! curl -fsSL --connect-timeout 8 -o "$tmp" "${RAW_BASE}/release/harden.sh"; then
    colorEcho ${RED} "拉最新 harden.sh 失败（网络或地址），保留旧版 ${HARDEN_VERSION}。"
    rm -f "$tmp"
    return 3
  fi
  if ! bash -n "$tmp" 2>/dev/null || ! grep -q '^HARDEN_VERSION=' "$tmp"; then
    colorEcho ${RED} "下载内容不是合法 harden.sh（语法不过或缺版本标记），不覆盖，保留旧版。"
    rm -f "$tmp"
    return 1
  fi
  remote_ver=$(awk -F"'" '/^HARDEN_VERSION=/{print $2; exit}' "$tmp")
  if [[ "$remote_ver" == "$HARDEN_VERSION" && -f "$target" ]]; then
    colorEcho ${GREEN} "已是最新：${HARDEN_VERSION}（${target}）。"
    rm -f "$tmp"
    return 0
  fi
  chmod +x "$tmp"
  if ! mv -f "$tmp" "$target"; then
    colorEcho ${RED} "覆盖 ${target} 失败，保留旧版。"
    rm -f "$tmp"
    return 1
  fi
  colorEcho ${GREEN} "harden 脚本已更新：${HARDEN_VERSION} -> ${remote_ver}（${target}）。"
  return 0
}

Help() {
  cat - 1>&2 <<EOF
节点机一键前置配置 + 安全加固（独立于 deploy.sh，装机不隐含改整机）。

一键（变量写在 bash 前）：
  curl -fsSL --connect-timeout 8 ${RAW_BASE}/release/harden.sh \\
    | SSH_PUBKEY='ssh-ed25519 AAAA…' PANEL_IP='面板IP' PUSH_PORT='30108' ALLOW_PORTS='10000-20000' bash -s --

变量：
  SSH_PUBKEY   运维公钥，给了才关密码登录（没给整段跳过）。一个服务商一把，在运维机上生成。
  SSH_ALLOW_USERS  SSH 白名单，默认只 root；个别机器要用别的登录账号设 'root <名字>'。
               被挡在外的现有登录账号（云镜像默认用户如 admin）会提示，不静默锁人。
  ALLOW_PORTS  业务口：'443' 单端口 / '10000-20000' 多端口段（面板系统设置 min_port/max_port）/
               '443,8388,10000-20000' 混合；每项可带 /tcp /udp /both，默认 tcp+udp 都放行。
  PANEL_IP     面板出口 IP，管理口只对它开放。
  PUSH_PORT    节点管理口（面板节点编辑页 push_port），TCP。
  REBOOT_TIME  条件重启时刻，默认 05:00，三台错开各给不同值。
  DHCP=1       走 DHCP 续租时放行 UDP 67/68（默认自动探测）。
  AUTO_CONFIRM=1  跑完即确认、不起 10 分钟自动还原保险（默认仍起保险防锁死）。
               仅在你已验过密钥登录或自负锁死风险时用；退回仍走 --rollback。
  DDNS_DNS / DDNS_ID / DDNS_TOKEN / DDNS_IPV4  ddns 续租：提供方名 / 账号 / 密钥 / 域名（逗号分隔），
               只从环境变量或 secrets 注入，不写脚本里；缺一个就整段跳过（不装 ddns、不写配置、不装任务）。

子命令（写给 bash）：
  --confirm    开新会话确认能登录后取消 10 分钟自动还原。
  --auto-confirm  同 AUTO_CONFIRM=1。
  --rollback   删本脚本写的配置、还原 ufw/sshd、清 ddns 配置/任务/缓存；不卸载包。
  --status     只读一条读数。
  --self-update  拉最新 harden.sh 覆盖本地安装（stdin 形态装到 /usr/local/bin/vnet-harden）；
               下载失败/语法不过不覆盖。只升脚本自身，升 vnet 二进制走 upgrade.sh。
  --version    打印本脚本版本。
  -h, --help   本帮助。

做了什么：时区 Asia/Shanghai、vnstat、unattended-upgrades 安全补丁 + 条件重启、journald 限额、
fail2ban（递增封禁 + recidive）、SSH 密钥化（白名单默认 root、MaxStartups 限速、关 X11/agent 转发）、
ufw default-deny、AppArmor 启用断言；ddns 续租（pipx 装包、按注入参数生成配置、自检过才装 timer）。关密码与开防火墙后起 10 分钟自动还原保险，--confirm 取消。
判据与排障：https://github.com/ProxyPanel/VNet-SSR/tree/master/docs
EOF
}

main() {
  local mode='run'
  while [[ $# -gt 0 ]]; do
    case "$1" in
    --confirm) mode='confirm' ;;
    --auto-confirm) AUTO_CONFIRM=1 ;;
    --rollback) mode='rollback' ;;
    --status) mode='status' ;;
    --version) mode='version' ;;
    --self-update) mode='selfupdate' ;;
    -h | --help) mode='help' ;;
    *) colorEcho ${YELLOW} "忽略认不出的参数：$1（开关写给 bash：bash -s -- --status）" ;;
    esac
    shift
  done

  [[ "$mode" == 'help' ]] && { Help; return 0; }
  [[ "$mode" == 'status' ]] && { do_status; return 0; }
  [[ "$mode" == 'version' ]] && { echo "$HARDEN_VERSION"; return 0; }

  if [[ ${EUID} -ne 0 ]]; then
    colorEcho ${YELLOW} "不是 root，这次什么都没改（写 sshd/ufw/sysctl 都要 root）。"
    return 0
  fi
  # self-update 只换脚本文件，与发行版无关，放在 distro 守卫前
  if [[ "$mode" == 'selfupdate' ]]; then
    do_self_update
    return $?
  fi
  detect_distro
  if [[ "$DISTRO_ID" != 'debian' ]]; then
    colorEcho ${RED} "本脚本只在 Debian 上验证过（当前：${DISTRO_ID:-认不出}）：不在别的发行版上代按防火墙/SSH/定时 DDNS 续租，避免锁死。"
    return 1
  fi
  eol_warn
  if [[ -z "$SYSTEMCTL_CMD" ]]; then
    colorEcho ${RED} "没有 systemctl（本脚本靠 systemd 管服务与起自动还原保险与定时 DDNS 续租）：不在非 systemd 机器上代按。"
    return 1
  fi

  if [[ "$mode" == 'confirm' ]]; then
    do_confirm
    return 0
  fi
  if [[ "$mode" == 'rollback' ]]; then
    do_rollback
    return 0
  fi

  precheck_dpkg

  mkdir -p "$STATE_DIR"
  state_load
  apt_install curl ca-certificates || return 1

  sec_base
  sec_ddns
  sec_patch
  sec_logs
  sec_fail2ban
  sec_ssh
  sec_firewall
  check_apparmor
  arm_revert

  colorEcho ${GREEN} "== 加固流程跑完（各段做了什么/为什么没做，见上方输出）=="
  colorEcho ${BLUE} "看读数：bash harden.sh --status    退回原样：bash harden.sh --rollback"
  return 0
}

# 被源进做纯函数测试时不跑 main；直接执行与 curl|bash -s 都要跑。
# stdin 执行（bash -s）时 BASH_SOURCE[0] 为空、$0 是 bash，只判相等会把主调用路径整条跳过（静默无输出）
if [[ -z "${BASH_SOURCE[0]}" || "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi