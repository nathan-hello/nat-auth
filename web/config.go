package web

import (
	"crypto/rsa"
	"errors"
	"os"
	"time"

	"github.com/golang-jwt/jwe"
)

type configJwt struct {
	Secret        string
	SecureCookie  bool
	AccessExpiry  time.Duration
	RefreshExpiry time.Duration
	EnableJwe     bool
	PublicKey     *rsa.PublicKey
	PrivateKey    *rsa.PrivateKey
}

var jwtConfig *configJwt

type PasswordJwtParams struct {
	Secret         string
	PublicKeyPath  string
	PrivateKeyPath string
}

func InitJwt(params PasswordJwtParams) error {
	if params.Secret == "" {
		return errors.New("a secret string is required for signing the JWTs")
	}

	c := configJwt{
		Secret:        params.Secret,
		SecureCookie:  true,
		AccessExpiry:  15 * time.Minute,
		RefreshExpiry: 2 * time.Hour,
	}

	if params.PublicKeyPath != "" && params.PrivateKeyPath != "" {
		err := initJwe(&c, params)
		if err != nil {
			return err
		}
	}

	jwtConfig = &c
	return nil
}

func initJwe(c *configJwt, params PasswordJwtParams) error {
	var err error

	pubPem, err := os.ReadFile(params.PublicKeyPath)
	if err != nil {
		return err
	}

	privPem, err := os.ReadFile(params.PrivateKeyPath)
	if err != nil {
		return err
	}

	c.PublicKey, err = jwe.ParseRSAPublicKeyFromPEM(pubPem)
	if err != nil {
		return err
	}

	c.PrivateKey, err = jwe.ParseRSAPrivateKeyFromPEM(privPem)
	if err != nil {
		return err
	}

	c.EnableJwe = true
	return nil

}

func JwtConfig() *configJwt {
	if jwtConfig != nil {
		return jwtConfig
	}
	return nil
}
