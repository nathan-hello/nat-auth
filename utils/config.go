package utils

import (
	"time"
)

type ConfigJwt struct {
	Secret        string
	SecureCookie  bool
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
}

var localConfig *ConfigJwt

func InitJwt(c ConfigJwt) {
	localConfig = &c
}

func LocalConfig() *ConfigJwt {
	if localConfig != nil {
		return localConfig
	}
	return nil
}
