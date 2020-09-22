load("//release/bazel:build.bzl", "foreign_go_binary")
load("//release/bazel:gpg.bzl", "gpg_sign")
load("//release/bazel:matrix.bzl", "SUPPORTED_MATRIX")
load("//cmd/shadowsocksr-server:targets.bzl", "gen_targets")

package(default_visibility=["//visibility:public"])

gen_targets(SUPPORTED_MATRIX)

