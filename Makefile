LDFLAGS := -s -w
# The -w and -s flags reduce binary sizes by excluding unnecessary symbols and debug info

BINDIR := bin
DISTDIR := dist
SERVER_PKG := ./cmd/shadowsocksr-server
# 默认版本取 release/version.json 的 latest（部署/升级脚本判的就是这个字段），CI 用 tag 覆盖
VERSION ?= $(shell grep '"latest"' release/version.json | cut -d'"' -f4)

all:
	env CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/vnet_darwin_amd64 $(SERVER_PKG)
	env CGO_ENABLED=0 GOOS=freebsd GOARCH=386 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/vnet_freebsd_386 $(SERVER_PKG)
	env CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/vnet_freebsd_amd64 $(SERVER_PKG)
	env CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/vnet_linux_386 $(SERVER_PKG)
	env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/vnet_linux_amd64 $(SERVER_PKG)
	env CGO_ENABLED=0 GOOS=linux GOARCH=arm go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/vnet_linux_arm $(SERVER_PKG)
	env CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/vnet_linux_arm64 $(SERVER_PKG)
	env CGO_ENABLED=0 GOOS=windows GOARCH=386 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/vnet_windows_386.exe $(SERVER_PKG)
	env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/vnet_windows_amd64.exe $(SERVER_PKG)
	env CGO_ENABLED=0 GOOS=linux GOARCH=mips64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/vnet_linux_mips64 $(SERVER_PKG)
	env CGO_ENABLED=0 GOOS=linux GOARCH=mips64le go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/vnet_linux_mips64le $(SERVER_PKG)
	env CGO_ENABLED=0 GOOS=linux GOARCH=mips GOMIPS=softfloat go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/vnet_linux_mips $(SERVER_PKG)
	env CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/vnet_linux_mipsle $(SERVER_PKG)

clean:
	rm -rf $(BINDIR) $(DISTDIR)

# 资产名、包内目录名与三项内容都由 release/package.sh 按部署脚本的契约生成
package: all
	@bash release/package.sh $(VERSION)

.PHONY: all clean package
