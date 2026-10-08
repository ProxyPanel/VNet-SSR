#!/bin/bash

# 下发地址：https://raw.githubusercontent.com/ProxyPanel/VNet-SSR/master/release/deploy.sh

# If not specify, default meaning of return value:
# 0: Success
# 1: System error
# 2: Application error
# 3: Network error

RAW_BASE='https://raw.githubusercontent.com/ProxyPanel/VNet-SSR/master'

# CLI arguments
PROXY=''
HELP=''
FORCE=''
CHECK=''
REMOVE=''
VERSION=''
VSRC_ROOT='/tmp/vnet'
EXTRACT_ONLY=''
LOCAL=''
LOCAL_INSTALL=''
ERROR_IF_UPTODATE=''
DNSCACHE=''
TUNE=''
UNKNOWN=''

# 环境变量与命令行等价：curl|bash 的调用方只能传环境变量
[[ "$WITH_DNS_CACHE" == "1" ]] && DNSCACHE='1'
[[ "$WITH_TUNE" == "1" ]] && TUNE='1'

CUR_VER=""
NEW_VER=""
VDIS=''
ZIPFILE="/tmp/vnet/vnet.zip"

CMD_INSTALL=""
CMD_UPDATE=""
SOFTWARE_UPDATED=0

SYSTEMCTL_CMD=$(command -v systemctl 2>/dev/null)
SERVICE_CMD=$(command -v service 2>/dev/null)


#######color code########
RED="31m"    # Error message
GREEN="32m"  # Success message
YELLOW="33m" # Warning message
BLUE="36m"   # Info message

#########################
while [[ $# > 0 ]]; do
  case "$1" in
  -p | --proxy)
    PROXY="-x ${2}"
    shift # past argument
    ;;
  -h | --help)
    HELP="1"
    ;;
  -f | --force)
    FORCE="1"
    ;;
  -c | --check)
    CHECK="1"
    ;;
  --remove)
    REMOVE="1"
    ;;
  --version)
    VERSION="$2"
    shift
    ;;
  --extract)
    VSRC_ROOT="$2"
    shift
    ;;
  --extractonly)
    EXTRACT_ONLY="1"
    ;;
  -l | --local)
    LOCAL="$2"
    LOCAL_INSTALL="1"
    shift
    ;;
  --errifuptodate)
    ERROR_IF_UPTODATE="1"
    ;;
  --with-dns-cache)
    DNSCACHE="1"
    ;;
  -t | --tune)
    TUNE="1"
    ;;
  *)
    UNKNOWN="${UNKNOWN}${1} "
    ;;
  esac
  shift # past argument or value
done

###############################
colorEcho() {
  echo -e "\033[${1}${@:2}\033[0m" 1>&2
}

archAffix() {
  case "${1:-"$(uname -m)"}" in
  i686 | i386)
    echo '32'
    ;;
  x86_64 | amd64)
    echo '64'
    ;;
  *armv7* | armv6l)
    echo 'arm'
    ;;
  *armv8* | aarch64)
    echo 'arm64'
    ;;
  *mips64le*)
    echo 'mips64le'
    ;;
  *mips64*)
    echo 'mips64'
    ;;
  *mipsle*)
    echo 'mipsle'
    ;;
  *mips*)
    echo 'mips'
    ;;
  *s390x*)
    echo 's390x'
    ;;
  ppc64le)
    echo 'ppc64le'
    ;;
  ppc64)
    echo 'ppc64'
    ;;
  *)
    return 1
    ;;
  esac

  return 0
}

downloadVNet() {
  rm -rf /tmp/vnet
  mkdir -p /tmp/vnet
  DOWNLOAD_LINK="https://github.com/ProxyPanel/VNet-SSR/releases/download/${NEW_VER}/vnet-linux-${VDIS}.zip"
  colorEcho ${BLUE} "Downloading vnet: ${DOWNLOAD_LINK}"
  curl ${PROXY} -L -H "Cache-Control: no-cache" -o ${ZIPFILE} ${DOWNLOAD_LINK}
  if [ $? != 0 ]; then
    colorEcho ${RED} "Failed to download! Please check your network or try again."
    return 3
  fi
  return 0
}

installSoftware() {
  COMPONENT=$1
  if [[ -n $(command -v $COMPONENT) ]]; then
    return 0
  fi

  getPMT
  if [[ $? -eq 1 ]]; then
    colorEcho ${RED} "The system package manager tool isn't APT or YUM, please install ${COMPONENT} manually."
    return 1
  fi
  if [[ $SOFTWARE_UPDATED -eq 0 ]]; then
    colorEcho ${BLUE} "Updating software repo"
    # 刷新失败不能静默继续：发行版进归档后包列表是旧的，后面的安装会报 404，
    # 而 404 看起来像是脚本在装错东西
    if ! $CMD_UPDATE; then
      colorEcho ${YELLOW} "软件源刷新失败：这台机的发行版可能已进归档，先修 /etc/apt/sources.list 再重试。"
    fi
    SOFTWARE_UPDATED=1
  fi

  colorEcho ${BLUE} "Installing ${COMPONENT}"
  $CMD_INSTALL $COMPONENT
  if [[ $? -ne 0 ]]; then
    colorEcho ${RED} "Failed to install ${COMPONENT}. 若上面是 404，多半是软件源过期（见刷新失败那条），不是本脚本的问题。"
    return 1
  fi
  return 0
}

# return 1: not apt, yum, or zypper
getPMT() {
  if [[ -n $(command -v apt-get) ]]; then
    CMD_INSTALL="apt-get -y -qq install"
    CMD_UPDATE="apt-get -qq update"
  elif [[ -n $(command -v yum) ]]; then
    CMD_INSTALL="yum -y -q install"
    CMD_UPDATE="yum -q makecache"
  elif [[ -n $(command -v zypper) ]]; then
    CMD_INSTALL="zypper -y install"
    CMD_UPDATE="zypper ref"
  else
    return 1
  fi
  return 0
}

extract() {
  colorEcho ${BLUE}"Extracting vnet package to /tmp/vnet."
  mkdir -p /tmp/vnet
  unzip $1 -d ${VSRC_ROOT}
  if [[ $? -ne 0 ]]; then
    colorEcho ${RED} "Failed to extract vnet."
    return 2
  fi
  if [[ -d "/tmp/vnet/vnet-${NEW_VER}-linux-${VDIS}" ]]; then
    VSRC_ROOT="/tmp/vnet/vnet-${NEW_VER}-linux-${VDIS}"
  fi
  return 0
}

normalizeVersion() {
  if [ -n "$1" ]; then
    case "$1" in
    v*)
      echo "$1"
      ;;
    *)
      echo "v$1"
      ;;
    esac
  else
    echo ""
  fi
}

# 1: new VNet. 0: no. 2: not installed. 3: check failed. 4: don't check.
getVersion() {
  if [[ -n "$VERSION" ]]; then
    NEW_VER="$(normalizeVersion "$VERSION")"
    return 4
  else
    VER="$(/usr/bin/vnet/vnet --version 2>/dev/null)"
    RETVAL=$?
    CUR_VER="$(normalizeVersion "$(echo "$VER" | head -n 1 | cut -d " " -f2)")"
    TAG_URL="${RAW_BASE}/release/version.json"
    NEW_VER="$(normalizeVersion "$(curl ${PROXY} -s "${TAG_URL}" --connect-timeout 10 | grep 'latest' | cut -d\" -f4)")"

    if [[ $? -ne 0 ]] || [[ $NEW_VER == "" ]]; then
      colorEcho ${RED} "Failed to fetch release information. Please check your network or try again."
      return 3
    elif [[ $RETVAL -ne 0 ]]; then
      return 2
    elif [[ $NEW_VER != $CUR_VER ]]; then
      return 1
    fi
    return 0
  fi
}

stopVNet() {
  colorEcho ${BLUE} "Shutting down VNet service."
  if [[ -n "${SYSTEMCTL_CMD}" ]] || [[ -f "/lib/systemd/system/vnet.service" ]] || [[ -f "/etc/systemd/system/vnet.service" ]]; then
    ${SYSTEMCTL_CMD} stop vnet
  elif [[ -n "${SERVICE_CMD}" ]] || [[ -f "/etc/init.d/vnet" ]]; then
    ${SERVICE_CMD} vnet stop
  fi
  if [[ $? -ne 0 ]]; then
    colorEcho ${YELLOW} "Failed to shutdown VNet service."
    return 2
  fi
  return 0
}

startVNet() {
  if [ -n "${SYSTEMCTL_CMD}" ] && [[ -f "/lib/systemd/system/vnet.service" || -f "/etc/systemd/system/vnet.service" ]]; then
    ${SYSTEMCTL_CMD} start vnet
  elif [ -n "${SERVICE_CMD}" ] && [ -f "/etc/init.d/vnet" ]; then
    ${SERVICE_CMD} vnet start
  fi
  if [[ $? -ne 0 ]]; then
    colorEcho ${YELLOW} "Failed to start VNet service."
    return 2
  fi
  return 0
}

copyFile() {
  NAME=$1
  ERROR=$(cp "${VSRC_ROOT}/${NAME}" "/usr/bin/vnet/${NAME}" 2>&1)
  if [[ $? -ne 0 ]]; then
    colorEcho ${YELLOW} "${ERROR}"
    return 1
  fi
  return 0
}

makeExecutable() {
  chmod +x "/usr/bin/vnet/$1"
}

VNET_BIN='/usr/bin/vnet/vnet'
VNET_LINK='/usr/local/bin/vnet'

# 软链只是给人用的便利：服务的 ExecStart 与 getVersion 都走绝对路径，链坏了不影响节点跑
linkIsOurs() {
  [[ "$(readlink "$VNET_LINK")" == "$VNET_BIN" ]]
}

makeSymlink() {
  # readlink 不带 -f：卸载后链是悬空的，-f 要求中间目录存在会失败
  if { [[ -e "$VNET_LINK" ]] || [[ -L "$VNET_LINK" ]]; } && ! linkIsOurs; then
    colorEcho ${YELLOW} "$VNET_LINK 已被其它程序占用，不覆盖；用 $VNET_BIN 调用。"
    return 0
  fi
  mkdir -p "$(dirname "$VNET_LINK")" && ln -sf "$VNET_BIN" "$VNET_LINK"
  return 0
}

removeSymlink() {
  # 只删自己建的那条，别人的同名文件不动
  if linkIsOurs; then
    rm -f "$VNET_LINK"
  fi
  return 0
}

installVNet() {
  # Install VNet binary to /usr/bin/vnet
  remove
  mkdir -p /usr/bin/vnet
  copyFile vnet
  if [[ $? -ne 0 ]]; then
    colorEcho ${RED} "Failed to copy VNet binary and resources."
    return 1
  fi
  makeExecutable vnet
  makeSymlink

  # Install VNet server config to /etc/vnet
  if [[ ! -f "/etc/vnet/config.json" ]]; then
    mkdir -p /etc/vnet
    mkdir -p /var/log/vnet
    cp "${VSRC_ROOT}/config.json" "/etc/vnet/config.json"
    if [[ $? -ne 0 ]]; then
      colorEcho ${YELLOW} "Failed to create VNet configuration file. Please create it manually."
      return 1
    fi
  fi

  if [[ -n "${NODE_ID}" ]];then
        sed -i "s|\"api_host\"\:[^,]*|\"api_host\": \"${WEB_API}\"|g" "/etc/vnet/config.json"
        sed -i "s|\"node_id\"\:[^,]*|\"node_id\": ${NODE_ID}|g" "/etc/vnet/config.json"
        sed -i "s|\"key\"\:[^,]*|\"key\": \"${NODE_KEY}\"|g" "/etc/vnet/config.json"

        colorEcho ${BLUE} "web_api:${WEB_API}"
        colorEcho ${BLUE} "node_id:${NODE_ID}"
        colorEcho ${BLUE} "node_key:${NODE_KEY}"
    fi

  return 0
}

installInitScript() {
  if [[ -n "${SYSTEMCTL_CMD}" ]] && [[ ! -f "/etc/systemd/system/vnet.service" && ! -f "/lib/systemd/system/vnet.service" ]]; then
    cp "${VSRC_ROOT}/systemd/vnet.service" "/etc/systemd/system/"
    systemctl enable vnet.service
  elif [[ -n "${SERVICE_CMD}" ]] && [[ ! -f "/etc/init.d/vnet" ]]; then
    installSoftware "daemon" || return $?
    cp "${VSRC_ROOT}/systemv/vnet" "/etc/init.d/vnet"
    chmod +x "/etc/init.d/vnet"
    update-rc.d vnet defaults
  fi
}

Help() {
  cat - 1>&2 <<EOF
面板后台复制的那条命令不用改：它只装节点，装完会顺手把这台机器的体检结果打出来，
要不要更进一步由你决定。要加东西只记一个位置 —— 写在管道末尾 bash 前面的变量串里：

  curl -s <地址> | WEB_API="..." NODE_ID=1 NODE_KEY=... WITH_TUNE=1 bash

  WITH_TUNE=1        装完跑 release/tune.sh 调系统参数（写 sysctl 等四处，不动 sshd 与防火墙，
                     不重启 vnet；改完想立即生效就自己 systemctl restart vnet）
  WITH_DNS_CACHE=1   装 dnsmasq 做本机解析缓存（只监听 127.0.0.1；验证不过会还原 resolv.conf）
  WEB_API/NODE_ID/NODE_KEY  三个都给才会改写 /etc/vnet/config.json

命令行形式（下载下来直接跑脚本时才用得上，开关要写给 bash 不是写给 curl）：
  bash deploy.sh [-h] [-c] [--remove] [-p proxy] [-f] [--version vx.y.z] [-l file] [-t]
    -h, --help            本帮助
    -p, --proxy           走代理下载，如 -p socks5://127.0.0.1:1080 或 -p http://127.0.0.1:3128
    -f, --force           版本相同也重装
    -c, --check           只查有没有新版
    -l, --local FILE      从本地包装
        --remove          卸载
        --tune, -t        同 WITH_TUNE=1
        --with-dns-cache  同 WITH_DNS_CACHE=1
        --version vx.y.z  装指定版本
        --errifuptodate   已是最新版时以 10 退出
        --extract DIR     解包到指定目录（配 --extractonly 只解不装）
EOF
}

remove() {
  removeSymlink
  if [[ -n "${SYSTEMCTL_CMD}" ]] && [[ -f "/etc/systemd/system/vnet.service" ]]; then
    if pgrep "vnet" >/dev/null; then
      stopVNet
    fi
    systemctl disable vnet.service
    rm -rf "/usr/bin/vnet" "/etc/systemd/system/vnet.service" "/etc/vnet/config.json"
    if [[ $? -ne 0 ]]; then
      colorEcho ${RED} "Failed to remove VNet."
      return 0
    else
      colorEcho ${GREEN} "Removed VNet successfully."
      return 0
    fi
  elif [[ -n "${SYSTEMCTL_CMD}" ]] && [[ -f "/lib/systemd/system/vnet.service" ]]; then
    if pgrep "vnet" >/dev/null; then
      stopVNet
    fi
    systemctl disable vnet.service
    rm -rf "/usr/bin/vnet" "/lib/systemd/system/vnet.service" "/etc/vnet/config.json"
    if [[ $? -ne 0 ]]; then
      colorEcho ${RED} "Failed to remove VNet."
      return 0
    else
      colorEcho ${GREEN} "Removed VNet successfully."
      return 0
    fi
  elif [[ -n "${SERVICE_CMD}" ]] && [[ -f "/etc/init.d/vnet" ]]; then
    if pgrep "vnet" >/dev/null; then
      stopVNet
    fi
    rm -rf "/usr/bin/vnet" "/etc/init.d/vnet" "/etc/vnet/config.json"
    if [[ $? -ne 0 ]]; then
      colorEcho ${RED} "Failed to remove VNet."
      return 0
    else
      colorEcho ${GREEN} "Removed VNet successfully."
      return 0
    fi
  else
    colorEcho ${YELLOW} "VNet not found."
    return 0
  fi
}

checkUpdate() {
  echo "Checking for update."
  VERSION=""
  getVersion
  RETVAL="$?"
  if [[ $RETVAL -eq 1 ]]; then
    colorEcho ${BLUE} "Found new version ${NEW_VER} for VNet.(Current version:$CUR_VER)"
  elif [[ $RETVAL -eq 0 ]]; then
    colorEcho ${BLUE} "No new version. Current version is ${NEW_VER}."
  elif [[ $RETVAL -eq 2 ]]; then
    colorEcho ${YELLOW} "No VNet installed."
    colorEcho ${BLUE} "The newest version for VNet is ${NEW_VER}."
  fi
  return 0
}

# 时长判据的地基：date 不支持 %N 时返回 1，调用方整段静默，绝不拿整数秒冒充毫秒
nowMs() {
  local n
  n=$(date +%s%N 2>/dev/null)
  [[ "$n" =~ ^[0-9]+$ ]] || return 1
  echo $((n / 1000000))
}

DNS_COLD_MS=''
DNS_REPEAT_MS=''
DNS_BEFORE_REPEAT=''
DNS_FAIL=0

# 三个不同域名的冷查，外加对第一个域名的一次重复查：只有后者是本机缓存能整笔删掉的开销
measureDns() {
  local doms=(github.com cloudflare.com google.com)
  local d t1 t2 times=()

  DNS_COLD_MS='' DNS_REPEAT_MS='' DNS_FAIL=0
  # 探测工具不存在时返回 1：这是「没测」，不能报成「域名解析不出来」
  command -v getent >/dev/null 2>&1 || return 1
  for d in "${doms[@]}"; do
    t1=$(nowMs) || return 1
    getent hosts "$d" >/dev/null 2>&1 || DNS_FAIL=1
    t2=$(nowMs) || return 1
    ((t2 >= t1)) && times+=($((t2 - t1)))
  done
  t1=$(nowMs) || return 1
  getent hosts "${doms[0]}" >/dev/null 2>&1 || DNS_FAIL=1
  t2=$(nowMs) || return 1
  ((t2 >= t1)) && DNS_REPEAT_MS=$((t2 - t1))

  DNS_COLD_MS="${times[*]}"
  [[ -n "$DNS_COLD_MS" || -n "$DNS_REPEAT_MS" ]]
  return 0
}

# 首行指向回环才说明查询真的经过本机缓存
dnsCacheActive() {
  head -n 1 /etc/resolv.conf 2>/dev/null | grep -qE '^nameserver[[:space:]]+127\.0\.0\.1$'
}

# 只读探测：慢就给出对应这一档的可执行提示，本身不改任何文件。全快则完全不出声。
checkDnsResolution() {
  # repeat_warn 取 100ms：命中本机缓存是个位数毫秒，但只省下几十毫秒不值得为此多跑一个服务
  local cold_warn=1200 repeat_warn=100
  local v n=0 slow=0 max=0 managed=0

  measureDns || return 0
  [[ -n "$DNS_COLD_MS" || -n "$DNS_REPEAT_MS" ]] || return 0
  for v in $DNS_COLD_MS; do
    n=$((n + 1))
    ((v > max)) && max=$v
    ((v >= cold_warn)) && slow=$((slow + 1))
  done
  [[ -L /etc/resolv.conf ]] && managed=1
  # 两条独立的病：冷查持续慢（线路/上游）与重复查询仍然出网（本机没缓存）。偶发一次慢不算病。
  local cold_slow=0 cache_worth=0
  ((n > 0 && slow > 0 && slow * 2 >= n)) && cold_slow=1
  [[ -n "$DNS_REPEAT_MS" ]] && ((DNS_REPEAT_MS >= repeat_warn)) && cache_worth=1

  ((DNS_FAIL)) && colorEcho ${YELLOW} "有探测域名在这台机上没解析出来（超时与 NXDOMAIN 都长这样）：先单独复查 getent hosts github.com，别按慢查询处理它。"

  if dnsCacheActive; then
    if [[ -n "$DNS_BEFORE_REPEAT" && -n "$DNS_REPEAT_MS" ]]; then
      colorEcho ${GREEN} "本机缓存效果：重复查询 ${DNS_BEFORE_REPEAT}ms -> ${DNS_REPEAT_MS}ms。"
    fi
    ((cache_worth)) && colorEcho ${YELLOW} "缓存已生效但重复查询仍要 ${DNS_REPEAT_MS}ms：上游 TTL 太短，条目到期就被丢掉，要留住得配 min-cache-ttl。"
    ((cold_slow)) && colorEcho ${YELLOW} "冷查询最慢 ${max}ms、${slow}/${n} 次超过 ${cold_warn}ms：本机缓存省不掉这一笔，要换更近的上游或压超时。"
  elif ((cold_slow || cache_worth)); then
    ((cold_slow)) && colorEcho ${YELLOW} "冷查询最慢 ${max}ms、${slow}/${n} 次超过 ${cold_warn}ms：多半出站 UDP/53 在丢包，节点每见到一个新域名都要付一次这个钱。"
    if ((managed)); then
      colorEcho ${YELLOW} "  /etc/resolv.conf 是 systemd-resolved 的软链，本脚本不动它：上游走 /etc/systemd/resolved.conf.d/ 的 DNS=，压最坏等待用 DNSTimeout=，本机缓存开它自己的 Cache=yes。"
    else
      ((cold_slow)) && colorEcho ${YELLOW} "  先把最坏等待压下来：给 /etc/resolv.conf 追加 'options timeout:1 attempts:2'；还慢就换一个更近的上游。"
      ((cache_worth)) && colorEcho ${YELLOW} "  重复查同一个域名仍要 ${DNS_REPEAT_MS}ms，这台机没在缓存重复查询：把这一档留在本机，重跑本脚本加 --with-dns-cache。"
    fi
  fi

  return 0
}

# 带 --with-dns-cache 时先量一次，装完才有可对比的前后值
probeDnsPath() {
  if [[ "$DNSCACHE" == "1" ]]; then
    if measureDns && [[ -n "$DNS_REPEAT_MS" ]]; then
      DNS_BEFORE_REPEAT="$DNS_REPEAT_MS"
    fi
    configureDnsCache
  fi
  checkDnsResolution
  return 0
}

# tune.sh 不在发布包里，装的时候从 master 现取：改它立刻对新装生效，不用等发版打 tag
runTune() {
  local tune='/tmp/vnet-tune.sh'

  if ! curl ${PROXY} -fsSL "${RAW_BASE}/release/tune.sh" --connect-timeout 10 -o "$tune"; then
    colorEcho ${RED} "调优脚本没取到（${RAW_BASE}/release/tune.sh）：节点已经装好，只是没做系统调优。"
    return 0
  fi
  if bash "$tune"; then
    colorEcho ${GREEN} "调优这一步跑完了（改了什么、或为什么没做，都打印在上面）；要退回原样：bash $tune --rollback"
  else
    colorEcho ${RED} "调优脚本执行失败（上面是它的输出）：节点已经装好，系统配置没改完。"
  fi
  # 文件留着，--rollback 靠它；/tmp 下的一个小文件不值得为此再下一遍
  return 0
}

restoreResolvConf() {
  [[ -f /etc/resolv.conf.vnet-bak ]] && cp -a /etc/resolv.conf.vnet-bak /etc/resolv.conf
  colorEcho ${YELLOW} "已还原 /etc/resolv.conf；dnsmasq 的配置留在 /etc/dnsmasq.d/vnet.conf，可自行删除。"
}

stopDnsmasq() {
  if [[ -n "${SYSTEMCTL_CMD}" ]]; then
    systemctl stop dnsmasq >/dev/null 2>&1
  elif [[ -n "${SERVICE_CMD}" ]]; then
    service dnsmasq stop >/dev/null 2>&1
  fi
}

# dnsmasq 在这里只承担一件事：把重复的域名查询留在本机，别上那条会丢包的路。
# 三条硬约束：只监听回环（对外开 53 就是可被利用的 DNS 放大反射源）；resolv.conf 保留原上游作后备
# （否则 dnsmasq 一挂整机无解析）；装完必须断言实际监听地址与解析结果，不过就停服务并还原。
configureDnsCache() {
  local conf='/etc/dnsmasq.d/vnet.conf'
  local upstreams listening start secs s

  if [[ -L /etc/resolv.conf ]]; then
    colorEcho ${YELLOW} "/etc/resolv.conf 是软链（systemd-resolved 接管），跳过 dnsmasq：要换上游请改 resolved 的配置，别覆盖 stub。"
    return 0
  fi

  # 上游取自现有 resolv.conf；重复执行时首行已是 127.0.0.1，就沿用上次的记录
  upstreams=$(awk '$1=="nameserver" && $2!="127.0.0.1" {print $2}' /etc/resolv.conf)
  [[ -z "$upstreams" && -f "$conf" ]] && upstreams=$(sed -n 's/^server=\([0-9.]*\)$/\1/p' "$conf")
  if [[ -z "$upstreams" ]]; then
    colorEcho ${RED} "找不到可转发的上游 DNS，放弃配置（未改动任何文件）。"
    return 1
  fi

  # 先落配置再装包：避免发行版默认配置先把 53 开到所有网卡上
  mkdir -p /etc/dnsmasq.d
  {
    echo '# 由 release/deploy.sh --with-dns-cache 生成：只做本机缓存，不对外提供解析'
    echo 'listen-address=127.0.0.1'
    echo 'bind-interfaces'
    echo 'cache-size=2048'
    for s in $upstreams; do echo "server=$s"; done
  } > "$conf" || return 1

  installSoftware "dnsmasq" || return $?

  [[ -f /etc/resolv.conf.vnet-bak ]] || cp -a /etc/resolv.conf /etc/resolv.conf.vnet-bak
  {
    echo 'nameserver 127.0.0.1'
    for s in $upstreams; do echo "nameserver $s"; done
    echo 'options timeout:1 attempts:2'
  } > /etc/resolv.conf.tmp && mv -f /etc/resolv.conf.tmp /etc/resolv.conf

  if [[ -n "${SYSTEMCTL_CMD}" ]]; then
    systemctl enable dnsmasq >/dev/null 2>&1
    if ! systemctl restart dnsmasq; then
      colorEcho ${RED} "dnsmasq 起不来，还原 resolv.conf。"
      restoreResolvConf
      return 1
    fi
  elif [[ -n "${SERVICE_CMD}" ]]; then
    service dnsmasq restart || { restoreResolvConf; return 1; }
  else
    colorEcho ${RED} "没有 systemctl/service，无法管理 dnsmasq，还原 resolv.conf。"
    restoreResolvConf
    return 1
  fi

  # 断言监听地址：不假设发行版有没有把 /etc/dnsmasq.d 包含进去
  if command -v ss >/dev/null 2>&1; then
    listening=$(ss -lntu 'sport = :53' 2>/dev/null | tail -n +2)
    if ! echo "$listening" | grep -qE '(^|[[:space:]])127\.0\.0\.1:53([[:space:]]|$)'; then
      colorEcho ${RED} "dnsmasq 没能在 127.0.0.1:53 上服务（多半是 53 已被别的进程占住），还原 resolv.conf。"
      stopDnsmasq
      restoreResolvConf
      return 1
    fi
    if echo "$listening" | grep -vqE '(^|[[:space:]])(127\.0\.0\.1|\[::1\]):53([[:space:]]|$)'; then
      colorEcho ${RED} "dnsmasq 监听到了非回环地址（开放解析器风险），已停服务并还原 resolv.conf。"
      stopDnsmasq
      restoreResolvConf
      return 1
    fi
  else
    colorEcho ${YELLOW} "没有 ss 命令，无法断言监听地址：请自行确认 dnsmasq 只在 127.0.0.1 上服务。"
  fi

  start=$(date +%s)
  if ! getent hosts github.com >/dev/null 2>&1; then
    colorEcho ${RED} "改用本机缓存后解析失败，还原 resolv.conf。"
    restoreResolvConf
    return 1
  fi
  secs=$(( $(date +%s) - start ))
  if [[ $secs -gt 5 ]]; then
    colorEcho ${RED} "改用本机缓存后单次解析仍要 ${secs}s：上游本身不可用时缓存救不了，还原 resolv.conf。"
    restoreResolvConf
    return 1
  fi

  colorEcho ${GREEN} "本机 DNS 缓存就绪：单次解析 ${secs}s，转发上游 $(echo $upstreams)。（安装到断言之间可能有数秒默认配置已生效，必要时复查 ss -lntu 'sport = :53'）"
  return 0
}

main() {
  # 放在 main 里而不是参数循环后面：colorEcho 要到下面才定义，写早了这句根本打不出来
  if [[ -n "$UNKNOWN" ]]; then
    colorEcho ${YELLOW} "忽略了认不出的参数：${UNKNOWN}开关要写给 bash（bash -s -- --tune），写给 curl 会被 curl 吃掉；面板复制来的那条不用改，开关写在 bash 前面的变量串里就行（WITH_TUNE=1）。"
  fi
  #helping information
  [[ "$HELP" == "1" ]] && Help && return
  [[ "$CHECK" == "1" ]] && checkUpdate && return
  if [[ "$REMOVE" == "1" ]]; then
    remove
    colorEcho ${YELLOW} "系统调优改的是这台机器的配置，不属于节点卸载的范围：要退回原样跑 bash /tmp/vnet-tune.sh --rollback。"
    return
  fi

  local ARCH=$(uname -m)
  VDIS="$(archAffix)"

  # extract local file
  if [[ $LOCAL_INSTALL -eq 1 ]]; then
    colorEcho ${YELLOW} "Installing VNet via local file. Please make sure the file is a valid VNet package, as we are not able to determine that."
    NEW_VER=local
    installSoftware unzip || return $?
    rm -rf /tmp/vnet
    extract $LOCAL || return $?
  else
    # download via network and extract
    installSoftware "curl" || return $?
    getVersion
    RETVAL="$?"
    if [[ $RETVAL == 0 ]] && [[ "$FORCE" != "1" ]]; then
      colorEcho ${BLUE} "Latest version ${CUR_VER} is already installed."
      # 这条分支里 $VNET_BIN 一定存在（--version 刚成功过），所以老节点不带 -f 重跑一次就能补上软链
      makeSymlink
      probeDnsPath
      [[ "$TUNE" == "1" ]] && runTune
      if [ -n "${ERROR_IF_UPTODATE}" ]; then
        return 10
      fi
      return
    elif [[ $RETVAL == 3 ]]; then
      return 3
    else
      colorEcho ${BLUE} "Installing VNet ${NEW_VER} on ${ARCH}"
      downloadVNet || return $?
      installSoftware unzip || return $?
      extract ${ZIPFILE} || return $?
    fi
  fi

  if [ -n "${EXTRACT_ONLY}" ]; then
    colorEcho ${GREEN} "VNet extracted to ${VSRC_ROOT}, and exiting..."
    return 0
  fi

  if pgrep "vnet" >/dev/null; then
    stopVNet
  fi
  remove
  installVNet || return $?
  installInitScript || return $?
  colorEcho ${BLUE} "Starting VNet service."
  startVNet
  colorEcho ${GREEN} "VNet ${NEW_VER} is installed."
  probeDnsPath
  [[ "$TUNE" == "1" ]] && runTune
  rm -rf /tmp/vnet
  return 0
}

main