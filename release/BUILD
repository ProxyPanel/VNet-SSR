package(default_visibility = ["//visibility:public"])

load("//release/bazel:zip.bzl", "pkg_zip")
load("//release:mapping.bzl", "gen_mappings")

filegroup(
    name = "config_json",
    srcs = [
        "config.json",
    ],
)

filegroup(
    name = "systemd",
    srcs = [
        "systemd/vnet.service",
        "systemv/vnet",
    ],
)



pkg_zip(
    name = "vnet_darwin_amd64_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_darwin_amd64",
        "//cmd/shadowsocksr-server:vnet_darwin_amd64_sig",
    ],
    out = "vnet-macos.zip",
    mappings = gen_mappings("darwin", "amd64"),
)

pkg_zip(
    name = "vnet_windows_amd64_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_windows_amd64",
        "//cmd/shadowsocksr-server:vnet_windows_amd64_sig",
    ],
    out = "vnet-windows-64.zip",
    mappings = gen_mappings("windows", "amd64"),
)

pkg_zip(
    name = "vnet_windows_x86_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_windows_386",
        "//cmd/shadowsocksr-server:vnet_windows_386_sig",
    ],
    out = "vnet-windows-32.zip",
    mappings = gen_mappings("windows", "386"),
)

pkg_zip(
    name = "vnet_freebsd_amd64_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_freebsd_amd64",
        "//cmd/shadowsocksr-server:vnet_freebsd_amd64_sig",
    ],
    out = "vnet-freebsd-64.zip",
    mappings = gen_mappings("freebsd", "amd64"),
)

pkg_zip(
    name = "vnet_freebsd_x86_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_freebsd_386",
        "//cmd/shadowsocksr-server:vnet_freebsd_386_sig",
    ],
    out = "vnet-freebsd-32.zip",
    mappings = gen_mappings("freebsd", "386"),
)


pkg_zip(
    name = "vnet_openbsd_amd64_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_openbsd_amd64",
        "//cmd/shadowsocksr-server:vnet_openbsd_amd64_sig",
    ],
    out = "vnet-openbsd-64.zip",
    mappings = gen_mappings("openbsd", "amd64"),
)

pkg_zip(
    name = "vnet_openbsd_x86_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_openbsd_386",
        "//cmd/shadowsocksr-server:vnet_openbsd_386_sig",
    ],
    out = "vnet-openbsd-32.zip",
    mappings = gen_mappings("openbsd", "386"),
)

pkg_zip(
    name = "vnet_dragonfly_amd64_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_dragonfly_amd64",
        "//cmd/shadowsocksr-server:vnet_dragonfly_amd64_sig",
    ],
    out = "vnet-dragonfly-64.zip",
    mappings = gen_mappings("dragonfly", "amd64"),
)

pkg_zip(
    name = "vnet_linux_amd64_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_linux_amd64",
        "//cmd/shadowsocksr-server:vnet_linux_amd64_sig",
    ],
    out = "vnet-linux-64.zip",
    mappings = gen_mappings("linux", "amd64"),
)

pkg_zip(
    name = "vnet_linux_x86_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_linux_386",
        "//cmd/shadowsocksr-server:vnet_linux_386_sig",
    ],
    out = "vnet-linux-32.zip",
    mappings = gen_mappings("linux", "386"),
)

pkg_zip(
    name = "vnet_linux_arm_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_linux_arm",
        "//cmd/shadowsocksr-server:vnet_linux_arm_armv6",
        "//cmd/shadowsocksr-server:vnet_linux_arm_armv6_sig",
        "//cmd/shadowsocksr-server:vnet_linux_arm_armv7",
        "//cmd/shadowsocksr-server:vnet_linux_arm_armv7_sig",
        "//cmd/shadowsocksr-server:vnet_linux_arm_sig",
    ],
    out = "vnet-linux-arm.zip",
    mappings = gen_mappings("linux", "arm"),
)

pkg_zip(
    name = "vnet_linux_arm64_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_linux_arm64",
        "//cmd/shadowsocksr-server:vnet_linux_arm64_sig",
    ],
    out = "vnet-linux-arm64.zip",
    mappings = gen_mappings("linux", "arm64"),
)

pkg_zip(
    name = "vnet_linux_mips_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_linux_mips",
        "//cmd/shadowsocksr-server:vnet_linux_mips_sig",
        "//cmd/shadowsocksr-server:vnet_linux_mips_softfloat",
        "//cmd/shadowsocksr-server:vnet_linux_mips_softfloat_sig",
    ],
    out = "vnet-linux-mips.zip",
    mappings = gen_mappings("linux", "mips"),
)

pkg_zip(
    name = "vnet_linux_mipsle_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_linux_mipsle",
        "//cmd/shadowsocksr-server:vnet_linux_mipsle_sig",
        "//cmd/shadowsocksr-server:vnet_linux_mipsle_softfloat",
        "//cmd/shadowsocksr-server:vnet_linux_mipsle_softfloat_sig",
    ],
    out = "vnet-linux-mipsle.zip",
    mappings = gen_mappings("linux", "mipsle"),
)

pkg_zip(
    name = "vnet_linux_mips64_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_linux_mips64",
        "//cmd/shadowsocksr-server:vnet_linux_mips64_sig",
    ],
    out = "vnet-linux-mips64.zip",
    mappings = gen_mappings("linux", "mips64"),
)

pkg_zip(
    name = "vnet_linux_mips64le_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_linux_mips64le",
        "//cmd/shadowsocksr-server:vnet_linux_mips64le_sig",
    ],
    out = "vnet-linux-mips64le.zip",
    mappings = gen_mappings("linux", "mips64le"),
)

pkg_zip(
    name = "vnet_linux_s390x_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_linux_s390x",
        "//cmd/shadowsocksr-server:vnet_linux_s390x_sig",
    ],
    out = "vnet-linux-s390x.zip",
    mappings = gen_mappings("linux", "s390x"),
)

pkg_zip(
    name = "vnet_linux_ppc64_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_linux_ppc64",
        "//cmd/shadowsocksr-server:vnet_linux_ppc64_sig",
    ],
    out = "vnet-linux-ppc64.zip",
    mappings = gen_mappings("linux", "ppc64"),
)

pkg_zip(
    name = "vnet_linux_ppc64le_package",
    srcs = [
        ":config_json",
        ":systemd",
        "//cmd/shadowsocksr-server:vnet_linux_ppc64le",
        "//cmd/shadowsocksr-server:vnet_linux_ppc64le_sig",
    ],
    out = "vnet-linux-ppc64le.zip",
    mappings = gen_mappings("linux", "ppc64le"),
)
