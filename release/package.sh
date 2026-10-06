#!/bin/bash
# 按部署脚本 release/deplody.sh 的取包契约打包给 GitHub Release：
#   资产名 vnet-linux-<VDIS>.zip；解压后目录 vnet-<VERSION>-linux-<VDIS>/；
#   目录里必须有 vnet、config.json、systemd/vnet.service（脚本按这三项 copyFile/installInitScript）。
# 用法: bash release/package.sh v2.2.0      （VERSION 必须与 tag 名一致，脚本按 tag 拼下载URL）
set -euo pipefail

VERSION="${1:?用法: package.sh <版本号，需与 tag 名一致，如 v2.2.0>}"
BINDIR="${BINDIR:-bin}"
DISTDIR="${DISTDIR:-dist}"

cd "$(cd "$(dirname "$0")/.." && pwd)"

if ! command -v zip > /dev/null; then
  echo "缺少 zip 命令" >&2
  exit 1
fi

# 部署脚本 archAffix() 的返回值 : Makefile 产物里的 GOARCH 名
ARCH_MAP="32:386 64:amd64 arm:arm arm64:arm64 mips:mips mipsle:mipsle mips64:mips64 mips64le:mips64le"

rm -rf "$DISTDIR"
mkdir -p "$DISTDIR"

for pair in $ARCH_MAP; do
  vdis="${pair%%:*}"
  goarch="${pair##*:}"
  binary="$BINDIR/vnet_linux_$goarch"

  if [ ! -f "$binary" ]; then
    echo "缺少 $binary，请先跑 make" >&2
    exit 1
  fi

  root="vnet-$VERSION-linux-$vdis"
  rm -rf "$root"
  mkdir -p "$root/systemd"
  cp "$binary" "$root/vnet"
  cp release/config.json "$root/config.json"
  cp release/systemd/vnet.service "$root/systemd/vnet.service"
  zip -qr "$DISTDIR/vnet-linux-$vdis.zip" "$root"
  rm -rf "$root"

  echo "已打包 $DISTDIR/vnet-linux-$vdis.zip"
done
