def gen_mappings(os, arch):
  return {
    "vnet/release": "",
    "vnet/release/systemd": "systemd",
    "vnet/release/systemv": "systemv",
    "vnet/cmd/shadowsocksr-server/" + os + "/" + arch: "",
  }
