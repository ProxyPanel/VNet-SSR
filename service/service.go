package service

import (
	"github.com/rc452860/vnet/api/client"
	"github.com/rc452860/vnet/common/log"
	"github.com/rc452860/vnet/core"
	"os"
)

func Start() (err error) {
	if err = GetSSRManager().Start(); err != nil {
		return err
	}

	if err = GetRuleService().LoadFromApi(); err != nil {
		return err
	}

 	err = core.GetApp().Cron().AddFunc("@monthly", func() {
		if(!client.HasCertification(core.GetApp().ApiHost())){
			log.Error("vnet is unauthenticated")
			os.Exit(0)
		}
	})
	return err
}

func Reload() error {
	if err := GetSSRManager().Reload(); err != nil {
		return err
	}
	if err := GetRuleService().LoadFromApi(); err != nil {
		return err
	}
	return nil
}
