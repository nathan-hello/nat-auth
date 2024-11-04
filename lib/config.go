package lib

import (
	"time"

	"github.com/nathan-hello/nat-auth/db"
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

var localDb db.Accessor

func InitDb(c db.Accessor) {
	localDb = c
}

func LocalDb() db.Accessor {
	if localDb == nil {
		panic("natauth/lib/config.go could not find Db")
	}
	return localDb
}
