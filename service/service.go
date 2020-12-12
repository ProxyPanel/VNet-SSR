package service

func Start() (err error) {
	if err = GetSSRManager().Start(); err != nil {
		return err
	}

	if err = GetRuleService().LoadFromApi(); err != nil {
		return err
	}

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
