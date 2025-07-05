package utils

import (
	"crypto/rsa"
	"os"
	"time"

	"github.com/golang-jwt/jwe"
)

type ConfigJwt struct {
	Secret        string
	SecureCookie  bool
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
	PublicKey     *rsa.PublicKey
	PrivateKey    *rsa.PrivateKey
}

var localConfig *ConfigJwt

func InitJwt(c ConfigJwt, pub string, priv string) {
	pubPem, err := os.ReadFile(pub)
	if err != nil {
		Log("jwt").Warn("%s", err)
	}
	c.PublicKey, err = jwe.ParseRSAPublicKeyFromPEM(pubPem)
	if err != nil {
		Log("jwt").Warn("%s", err)
	}

	privPem, err := os.ReadFile(priv)
	if err != nil {
		Log("jwt").Warn("%s", err)
	}
	c.PrivateKey, err = jwe.ParseRSAPrivateKeyFromPEM(privPem)
	if err != nil {
		Log("jwt").Warn("%s", err)
	}

	localConfig = &c
}

func LocalConfig() *ConfigJwt {
	if localConfig != nil {
		return localConfig
	}
	return nil
}
