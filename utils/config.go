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
}

var localConfig *Config

func InitConfig(c Config) {
	localConfig = &c
}

func LocalConfig() *Config {
	if localConfig != nil {
		return localConfig
	}
	return &Config{
		ConfigJwt: ConfigJwt{
			Secret:        "secret",
			SecureCookie:  true,
			AccessExpiry:  1 * time.Hour,
			RefreshExpiry: 24 * time.Hour,
		},
	}
}
