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

type Config struct {
	ConfigJwt
	EmailRequired    bool
	UsernameRequired bool
	PasswordValidate func(string) bool
}

var initialized = 0
var localConfig *Config

func InitConfig(c Config) {
	localConfig = &c
}

func LocalConfig() *Config {
	if localConfig == nil {
		panic("natauth/lib/config.go could not find Config")
	}
	return localConfig
}
