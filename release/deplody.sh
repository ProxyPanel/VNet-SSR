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
    $CMD_UPDATE
    SOFTWARE_UPDATED=1
  fi

  colorEcho ${BLUE} "Installing ${COMPONENT}"
  $CMD_INSTALL $COMPONENT
  if [[ $? -ne 0 ]]; then
    colorEcho ${RED} "Failed to install ${COMPONENT}. Please install it manually."
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
    VER="$(/usr/bin/vnet -version 2>/dev/null)"
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
  rm -rf /tmp/vnet
  return 0
}

main