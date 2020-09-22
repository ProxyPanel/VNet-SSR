#!/bin/bash

OUTPUT=vnet
INPUT=cmd/shadowsocksr-server/main.go
APP_VERSION=

linux() {
  env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o bin/linux/$OUTPUT"_amd64" $INPUT
  upx --brute ./bin/linux/vnet_amd64 -o ./bin/linux/vnet
}

osx() {
  env CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -o bin/osx/$OUTPUT"_amd64" $INPUT
  upx --brute ./bin/osx/vnet_amd64 -o ./bin/osx/vnet
}

windows() {
  env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o bin/window/$OUTPUT"_amd64.exe" $INPUT
  upx --brute ./bin/windows/vnet_amd64 -o ./bin/windows/vnet
}

update_version() {
  sed -ie  "s/APP_VERSION = \"[^\"]*\"/APP_VERSION = \"$APP_VERSION\"/" ./core/version.go
}

clear() {
  rm -rf ./bin/*
}

clear
mkdir -p ./bin/out
read -r -p "select target os: [linux/windows/osx]" option

case $option in
linux)
  linux
  ;;
windows)
  windows
  ;;
osx)
  osx
  ;;
*)
  echo "invaild option"
  exit 1
  ;;
esac

