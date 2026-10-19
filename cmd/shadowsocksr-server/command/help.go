package command

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/ProxyPanel/VNet-SSR/common/log"
	"github.com/ProxyPanel/VNet-SSR/core"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:     filepath.Base(os.Args[0]),
	Short:   "SSR 协议节点后端，配合 OtakuCloud 面板使用",
	Long:    "vnet 启动时按 node_id 与 key 向面板拉本节点的监听配置与用户表，按端口起转发，\n再周期性上报流量、在线、心跳与审计命中。\n\n配置默认读当前目录的 config.json，用 --config 指定其它文件；四个键也能用同名命令行标志传。",
	Version: core.APP_VERSION,
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.Flags().String("config", "config.json", "配置文件路径")
	_ = viper.BindPFlag("config", rootCmd.Flags().Lookup("config"))

	// 部署脚本取的是这行的第二个字段（cut -d " " -f2）来和 version.json 比，格式不能改
	rootCmd.SetVersionTemplate(fmt.Sprintf("vnet %s\n", core.APP_VERSION))

	for _, item := range flagConfigs {
		if item.Default != nil {
			switch item.Type {
			case reflect.String:
				rootCmd.Flags().String(item.Name, item.Default.(string), item.Usage)
			case reflect.Int:
				rootCmd.Flags().Int(item.Name, item.Default.(int), item.Usage)
			case reflect.Bool:
				rootCmd.Flags().Bool(item.Name, item.Default.(bool), item.Usage)
			}
		} else {
			switch item.Type {
			case reflect.String:
				rootCmd.Flags().String(item.Name, "", item.Usage)
			case reflect.Int:
				rootCmd.Flags().Int(item.Name, 0, item.Usage)
			case reflect.Bool:
				rootCmd.Flags().Bool(item.Name, false, item.Usage)
			}
		}
		_ = viper.BindPFlag(item.Name, rootCmd.Flags().Lookup(item.Name))
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	viper.SetConfigFile(viper.GetString("config"))
	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		abspath, err := filepath.Abs(viper.ConfigFileUsed())
		if err != nil {
			panic(err)
		}
		fmt.Println("using config file:", abspath)
	}
}

func Execute(fn func()) {
	rootCmd.Run = runWrap(fn)
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func checkRequired() bool {
	for _, item := range flagConfigs {
		if item.Required {
			switch item.Type {
			case reflect.String:
				if viper.GetString(item.Name) == "" {
					log.Warn("miss param:%s", item.Name)
					return false
				}
			case reflect.Int:
				if viper.GetInt(item.Name) == 0 {
					log.Warn("miss param:%s", item.Name)
					return false
				}
			}
		}
	}
	return true
}

func runWrap(fn func()) func(cmd *cobra.Command, args []string) {
	return func(cmd *cobra.Command, args []string) {
		if !checkRequired() {
			_ = cmd.Help()
			return
		}
		fn()
	}
}
