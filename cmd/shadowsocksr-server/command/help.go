package command

// Copyright © 2019 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/rc452860/vnet/common/log"
	"github.com/rc452860/vnet/core"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var rootCmd = &cobra.Command{
	Use:   filepath.Base(os.Args[0]),
	Short: fmt.Sprintf("vnet version %s\r\n", core.APP_VERSION),
	Long:  fmt.Sprintf("vnet webapi version with ProxyPanel, current version: %s", core.APP_VERSION),
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.Flags().String("config", "config.json", "config file default: config.json")
	_ = viper.BindPFlag("config", rootCmd.Flags().Lookup("config"))

	// add version menu
	rootCmd.SetVersionTemplate(core.APP_VERSION)

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
					log.Warn("miss param:" + item.Name)
					return false
				}
			case reflect.Int:
				if viper.GetInt(item.Name) == 0 {
					log.Warn("miss param:" + item.Name)
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
