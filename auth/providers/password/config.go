package password

import (
	"crypto/rsa"
	"os"
	"time"

	"github.com/golang-jwt/jwe"
	"github.com/nathan-hello/nat-auth/logger"
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

type AuthParams struct {
	Secret         string
	PublicKeyPath  string
	PrivateKeyPath string
}

func InitJwt(params AuthParams) {
	c := ConfigJwt{
		Secret:        params.Secret,
		SecureCookie:  true,
		AccessExpiry:  15 * time.Minute,
		RefreshExpiry: 2 * time.Hour,
	}
	pubPem, err := os.ReadFile(params.PublicKeyPath)
	if err != nil {
		logger.Log("jwt").Warn("%s", err)
	}
	c.PublicKey, err = jwe.ParseRSAPublicKeyFromPEM(pubPem)
	if err != nil {
		logger.Log("jwt").Warn("%s", err)
	}

	privPem, err := os.ReadFile(params.PrivateKeyPath)
	if err != nil {
		logger.Log("jwt").Warn("%s", err)
	}
	c.PrivateKey, err = jwe.ParseRSAPrivateKeyFromPEM(privPem)
	if err != nil {
		logger.Log("jwt").Warn("%s", err)
	}

	localConfig = &c
}

func LocalConfig() *ConfigJwt {
	if localConfig != nil {
		return localConfig
	}
	return nil
}
