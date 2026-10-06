package service

import (
	"github.com/ProxyPanel/VNet-SSR/model"
)

func Start() (err error) {
	if err = GetSSRManager().Start(); err != nil {
		return err
	}

	if err = GetRuleService().LoadFromApi(); err != nil {
		return err
	}

	return err
}

// Reload 用调用方在关闭之前取好的全量集合重建服务：取不到集合时调用方不会走到这里
func Reload(users []*model.UserInfo) error {
	if err := GetSSRManager().Restart(users); err != nil {
		return err
	}
	if err := GetRuleService().LoadFromApi(); err != nil {
		return err
	}
	return nil
}
