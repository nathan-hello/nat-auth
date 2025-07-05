package httpwr

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwe"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/utils"
)

func SetTokenCookies(w http.ResponseWriter, a string, r string) {
	pk := utils.LocalConfig().PublicKey

	var atoken string
	var rtoken string
	ajwe, err := jwe.NewJWE(jwe.KeyAlgorithmRSAOAEP, pk, jwe.EncryptionTypeA256GCM, []byte(a))
	if err == nil {
		atoken, err = ajwe.CompactSerialize()
		if err != nil {
			atoken = a
			utils.Log("cookie").Warn("access-token could not be serialized")
		}
	} else {
		atoken = a
		utils.Log("cookie").Warn("access-token was not encrypted")
	}
	rjwe, err := jwe.NewJWE(jwe.KeyAlgorithmRSAOAEP, pk, jwe.EncryptionTypeA256GCM, []byte(a))
	if err == nil {
		rtoken, err = rjwe.CompactSerialize()
		if err != nil {
			rtoken = a
			utils.Log("cookie").Warn("access-token could not be serialized")
		}
	} else {
		rtoken = a
		utils.Log("cookie").Warn("access-token was not encrypted")
	}

	access := &http.Cookie{
		Name:     "access_token",
		Value:    atoken,
		Expires:  time.Now().Add(utils.LocalConfig().AccessExpiry),
		Secure:   utils.LocalConfig().SecureCookie,
		HttpOnly: utils.LocalConfig().SecureCookie,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, access)

	refresh := &http.Cookie{
		Name:     "refresh_token",
		Value:    rtoken,
		Expires:  time.Now().Add(utils.LocalConfig().RefreshExpiry),
		Secure:   utils.LocalConfig().SecureCookie,
		HttpOnly: utils.LocalConfig().SecureCookie,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	}

	http.SetCookie(w, refresh)
}

func GetJwtsFromCookie(r *http.Request) (string, string, error) {
	pk := utils.LocalConfig().PrivateKey

	access, err := r.Cookie("access_token")
	if err != nil {
		return "", "", err
	}

	refresh, err := r.Cookie("refresh_token")
	if err != nil {
		return "", "", err
	}

	var at []byte
	var rt []byte
	if pk != nil {
		utils.Log("jwt").Debug("BINGUS")
		ajwe, err := jwe.ParseEncrypted(access.Value)
		if err != nil {
			return "", "", err
		}

		at, err = ajwe.Decrypt(pk)
		if err != nil {
			return "", "", err
		}

		rjwe, err := jwe.ParseEncrypted(refresh.Value)
		if err != nil {
			return "", "", err
		}

		rt, err = rjwe.Decrypt(pk)
		if err != nil {
			return "", "", err
		}
	}

	return string(at), string(rt), nil
}

func DeleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func ParseRefreshOrDeleteToken(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	access, refresh, err := GetJwtsFromCookie(r)
	if err != nil {

	}

	vAccess, vRefresh, err := auth.ParseOrRefreshToken(access, refresh)

	if err != nil {
		DeleteCookie(w, "access_token")
		DeleteCookie(w, "refresh_token")
		return "", "", false
	}

	if vAccess != access || vRefresh != refresh {
		SetTokenCookies(w, vAccess, vRefresh)
		return vAccess, vRefresh, true
	}

	return vAccess, vRefresh, true
}
