#!/bin/bash

# 下发地址：https://raw.githubusercontent.com/ProxyPanel/VNet-SSR/master/release/upgrade.sh
#
# 只升级二进制：不碰 /etc/vnet/config.json、不碰 systemd 单元、不碰系统调优、不需要凭据。
# 新版起不来会自动回滚到旧版再退出，节点不会因为一次坏包躺平。
#
# 单节点（节点上直接跑，重复跑无害——已是最新会直接退出）：
#   curl -fsSL https://raw.githubusercontent.com/ProxyPanel/VNet-SSR/master/release/upgrade.sh | bash
#
# 多节点（跳板机上跑，nodes.txt 一行一个 IP；任一节点失败即停，不带病滚全池）：
#   for h in $(cat nodes.txt); do echo "== $h"; ssh -o BatchMode=yes "root@$h" \
#     'curl -fsSL https://raw.githubusercontent.com/ProxyPanel/VNet-SSR/master/release/upgrade.sh | bash' || break; done
#
# 开关写给 bash 不是写给 curl（curl|bash 时：bash -s -- --check）：
#   -c, --check            只查有没有新版（0=已最新，10=有新版可升）
#   -f, --force            版本相同也重装
#   -p, --proxy URL        走代理下载，如 -p http://127.0.0.1:3128
#       --version vX.Y.Z   升到/退到指定版本（退旧版就是手动回滚的通道）
#
# 退出码：0 成功或已是最新；1 环境错误（未装 vnet、缺 curl/unzip、坏包）；
#         2 新版启动失败（已回滚到旧版）；3 拿不到包（网络失败，或该版本没有发布产物）；10 --check 发现有新版
#
# 首次安装仍走 deploy.sh（建配置、装单元、可选调优）；本脚本假设节点已由 deploy.sh 装好。
# 包名与下载 URL 格式与 deploy.sh 一致，源头是 release CI 的发布产物与 release/version.json。

RAW_BASE='https://raw.githubusercontent.com/ProxyPanel/VNet-SSR/master'
VNET_BIN='/usr/bin/vnet/vnet'
BACKUP_BIN='/usr/bin/vnet/vnet.bak'
VSRC_ROOT='/tmp/vnet-upgrade'
ZIPFILE='/tmp/vnet-upgrade/vnet.zip'

SYSTEMCTL_CMD=$(command -v systemctl 2>/dev/null)
SERVICE_CMD=$(command -v service 2>/dev/null)

RED="31m"
GREEN="32m"
YELLOW="33m"
BLUE="36m"

CHECK=''
FORCE=''
PROXY=''
VERSION=''
CUR_VER=''
NEW_VER=''
VDIS=''

while [[ $# > 0 ]]; do
  case "$1" in
  -c | --check)
    CHECK="1"
    ;;
  -f | --force)
    FORCE="1"
    ;;
  -p | --proxy)
    PROXY="-x ${2}"
    shift
    ;;
  --version)
    VERSION="$2"
    shift
    ;;
  *)
    echo "忽略认不出的参数：$1" 1>&2
    ;;
  esac
  shift
done

colorEcho() {
  echo -e "\033[${1}${@:2}\033[0m" 1>&2
}

# 与 deploy.sh 的 archAffix 同一张表：发布产物按这套 GOARCH 命名
archAffix() {
  case "${1:-"$(uname -m)"}" in
  i686 | i386) echo '32' ;;
  x86_64 | amd64) echo '64' ;;
  *armv7* | armv6l) echo 'arm' ;;
  *armv8* | aarch64) echo 'arm64' ;;
  *mips64le* | *mips64el*) echo 'mips64le' ;;
  *mips64*) echo 'mips64' ;;
  *mipsle* | *mipsel*) echo 'mipsle' ;;
  *mips*) echo 'mips' ;;
  *s390x*) echo 's390x' ;;
  ppc64le) echo 'ppc64le' ;;
  ppc64) echo 'ppc64' ;;
  *) return 1 ;;
  esac
  return 0
}

normalizeVersion() {
  if [ -n "$1" ]; then
    case "$1" in
    v*) echo "$1" ;;
    *) echo "v$1" ;;
    esac
  else
    echo ""
  fi
}

# 版本对账：本机二进制 --version 与 version.json 的 latest（--version 指定时以指定为准）
getVersion() {
  if [[ -n "$VERSION" ]]; then
    NEW_VER="$(normalizeVersion "$VERSION")"
    CUR_VER="$(normalizeVersion "$( "$VNET_BIN" --version 2>/dev/null | head -n 1 | cut -d " " -f2 )")"
    return 0
  fi
  CUR_VER="$(normalizeVersion "$( "$VNET_BIN" --version 2>/dev/null | head -n 1 | cut -d " " -f2 )")"
  if [[ -z "$CUR_VER" ]]; then
    colorEcho ${RED} "取不到 $VNET_BIN 的版本——首次安装请用 deploy.sh（面板后台的部署命令），本脚本只负责升级。"
    return 1
  fi
  NEW_VER="$(normalizeVersion "$(curl ${PROXY} -s "${RAW_BASE}/release/version.json" --connect-timeout 10 | grep 'latest' | cut -d\" -f4)")"
  if [[ -z "$NEW_VER" ]]; then
    colorEcho ${RED} "取不到 release/version.json 的最新版号，网络问题稍后再试。"
    return 3
  fi
  return 0
}

downloadAndExtract() {
  rm -rf "$VSRC_ROOT"
  mkdir -p "$VSRC_ROOT"
  local link="https://github.com/ProxyPanel/VNet-SSR/releases/download/${NEW_VER}/vnet-linux-${VDIS}.zip"
  colorEcho ${BLUE} "下载 ${link}"
  # -f 是判据的全部：没有它，404 的 9 字节正文会被当成包落进 ZIPFILE，报成「包不完整」
  local rc=0 http_code
  http_code="$(curl ${PROXY} -f -L -H "Cache-Control: no-cache" -o "${ZIPFILE}" -w '%{http_code}' "${link}")" || rc=$?
  if [[ "$rc" == 22 ]]; then
    colorEcho ${RED} "拿不到 ${NEW_VER} 的 linux-${VDIS} 发布包（HTTP ${http_code}）。包按 tag 推送后的 CI 发布：tag 没推上去、或发布 job 还没跑完时这里就是 404，用 --version 指定一个已发布的版本即可落地。"
    return 3
  fi
  if [[ "$rc" != 0 ]]; then
    colorEcho ${RED} "下载失败（curl ${rc}），检查网络或重试。"
    return 3
  fi
  if ! unzip -q "$ZIPFILE" -d "$VSRC_ROOT"; then
    colorEcho ${RED} "解压失败：下载是完整的，但内容不是 zip（坏包，不是版本不存在）。"
    return 1
  fi
  # 发布包的目录名带版本与平台（同 deploy.sh 的 extract）
  if [[ -d "$VSRC_ROOT/vnet-${NEW_VER}-linux-${VDIS}" ]]; then
    VSRC_ROOT="$VSRC_ROOT/vnet-${NEW_VER}-linux-${VDIS}"
  fi
  if [[ ! -f "$VSRC_ROOT/vnet" ]]; then
    colorEcho ${RED} "解压后没找到 vnet 二进制（平台 linux-${VDIS} 可能没有 ${NEW_VER} 的发布产物）。"
    return 1
  fi
  return 0
}

serviceActive() {
  if [[ -n "$SYSTEMCTL_CMD" ]]; then
    "$SYSTEMCTL_CMD" is-active --quiet vnet
  else
    pgrep vnet >/dev/null
  fi
}

stopVNet() {
  colorEcho ${BLUE} "停止 vnet 服务。"
  if [[ -n "$SYSTEMCTL_CMD" ]]; then
    "$SYSTEMCTL_CMD" stop vnet
  elif [[ -n "$SERVICE_CMD" ]]; then
    "$SERVICE_CMD" vnet stop
  fi
}

startVNet() {
  if [[ -n "$SYSTEMCTL_CMD" ]]; then
    "$SYSTEMCTL_CMD" start vnet
  elif [[ -n "$SERVICE_CMD" ]]; then
    "$SERVICE_CMD" vnet start
  fi
}

# 新版起不来就换回旧二进制并拉起旧版；回滚也失败时留下手工指令
upgrade() {
  local newbin="$VSRC_ROOT/vnet"
  chmod +x "$newbin"
  local got
  got="$(normalizeVersion "$( "$newbin" --version 2>/dev/null | head -n 1 | cut -d " " -f2 )")"
  if [[ "$got" != "$NEW_VER" ]]; then
    colorEcho ${RED} "下载的二进制版本对不上（期望 ${NEW_VER}，实际 ${got:-无法执行}），不安装。"
    return 1
  fi

  stopVNet
  cp -f "$VNET_BIN" "$BACKUP_BIN" || { startVNet; return 1; }
  # 先解链再拷：对运行中的二进制原地覆写会 ETXTBSY；unlink 后旧 inode 归进程自用，新文件干净落位
  if ! rm -f "$VNET_BIN" || ! cp "$newbin" "$VNET_BIN" || ! chmod +x "$VNET_BIN"; then
    colorEcho ${RED} "写入新二进制失败，回滚。"
    mv -f "$BACKUP_BIN" "$VNET_BIN"
    startVNet
    return 1
  fi

  startVNet
  sleep 3
  local after
  after="$(normalizeVersion "$( "$VNET_BIN" --version 2>/dev/null | head -n 1 | cut -d " " -f2 )")"
  if serviceActive && [[ "$after" == "$NEW_VER" ]]; then
    colorEcho ${GREEN} "升级完成：${CUR_VER} → ${NEW_VER}（配置未动）。回滚通道：$0 --version ${CUR_VER}"
    return 0
  fi

  colorEcho ${RED} "新版没起来或版本不符（期望 ${NEW_VER}，实际 ${after:-无}），回滚到 ${CUR_VER}。"
  mv -f "$BACKUP_BIN" "$VNET_BIN"
  chmod +x "$VNET_BIN"
  startVNet
  sleep 3
  if serviceActive; then
    colorEcho ${YELLOW} "已回滚到 ${CUR_VER}，节点恢复服务。"
  else
    colorEcho ${RED} "回滚后仍未起来，手工检查：systemctl status vnet / journalctl -u vnet；旧二进制备份在 $BACKUP_BIN。"
  fi
  return 2
}

main() {
  if [[ ! -f "$VNET_BIN" ]]; then
    colorEcho ${RED} "$VNET_BIN 不存在——首次安装请用面板后台的部署命令（deploy.sh），本脚本只负责升级。"
    return 1
  fi
  command -v curl >/dev/null || { colorEcho ${RED} "缺 curl，先装它或走 deploy.sh。"; return 1; }
  command -v unzip >/dev/null || { colorEcho ${RED} "缺 unzip，先装它或走 deploy.sh。"; return 1; }

  VDIS="$(archAffix)" || { colorEcho ${RED} "认不出的 CPU 架构 $(uname -m)，发布清单里没有对应产物。"; return 1; }

  getVersion || return $?

  if [[ "$CHECK" == "1" ]]; then
    if [[ "$NEW_VER" == "$CUR_VER" ]]; then
      colorEcho ${BLUE} "已是最新：${CUR_VER}"
      return 0
    fi
    colorEcho ${BLUE} "有新版：${CUR_VER} → ${NEW_VER}"
    return 10
  fi

  if [[ "$NEW_VER" == "$CUR_VER" && "$FORCE" != "1" ]]; then
    colorEcho ${BLUE} "已是最新：${CUR_VER}，不升级（重装请加 -f）。"
    return 0
  fi

  colorEcho ${BLUE} "升级 vnet：${CUR_VER} → ${NEW_VER}（平台 linux-${VDIS}）"
  downloadAndExtract || return $?
  upgrade || return $?
  rm -rf /tmp/vnet-upgrade
  return 0
}

main "$@"
