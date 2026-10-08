#!/bin/bash

# This file is accessible as https://install.direct/go.sh
# Original source is located at github.com/vnet/vnet-core/release/install-release.sh

# If not specify, default meaning of return value:
# 0: Success
# 1: System error
# 2: Application error
# 3: Network error

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

# 环境变量与命令行等价：curl|bash 的调用方只能传环境变量
[[ "$WITH_DNS_CACHE" == "1" ]] && DNSCACHE='1'

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
  *)
    # unknown option
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
    TAG_URL="https://raw.githubusercontent.com/ProxyPanel/VNet-SSR/master/release/version.json"
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
./install-release.sh [-h] [-c] [--remove] [-p proxy] [-f] [--version vx.y.z] [-l file]
  -h, --help            Show help
  -p, --proxy           To download through a proxy server, use -p socks5://127.0.0.1:1080 or -p http://127.0.0.1:3128 etc
  -f, --force           Force install
      --version         Install a particular version, use --version v3.15
  -l, --local           Install from a local file
      --remove          Remove installed VNet
  -c, --check           Check for update
      --with-dns-cache  装 dnsmasq 做本机解析缓存（只监听 127.0.0.1；验证不过会还原 resolv.conf）
      --node_id         node_id for vnetpanel
      --node_key        node_key for vnetpanel
      --api_server      api_server for vnetpanel
EOF
}

remove() {
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

# 单次解析耗时判据：慢就给出可执行的提示，本身不改任何文件
checkDnsLatency() {
  local start secs
  start=$(date +%s)
  getent hosts github.com >/dev/null 2>&1
  secs=$(( $(date +%s) - start ))
  if [[ $secs -ge 2 ]]; then
    colorEcho ${YELLOW} "本机单次 DNS 查询耗时 ${secs}s：出站 UDP/53 丢包时，节点每个新建连都要等它。"
    colorEcho ${YELLOW} "先把最坏等待压下来：给 /etc/resolv.conf 追加 'options timeout:1 attempts:2'；"
    colorEcho ${YELLOW} "再把重复查询留在本机：重跑本脚本加 --with-dns-cache。"
  fi
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
    echo '# 由 release/deplody.sh --with-dns-cache 生成：只做本机缓存，不对外提供解析'
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
  #helping information
  [[ "$HELP" == "1" ]] && Help && return
  [[ "$CHECK" == "1" ]] && checkUpdate && return
  [[ "$REMOVE" == "1" ]] && remove && return

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
      [[ "$DNSCACHE" == "1" ]] && configureDnsCache
      checkDnsLatency
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
  [[ "$DNSCACHE" == "1" ]] && configureDnsCache
  checkDnsLatency
  rm -rf /tmp/vnet
  return 0
}

main