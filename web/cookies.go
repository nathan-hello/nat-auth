package web

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwe"
)

func encryptOrSkip(access, refresh string) (string, string) {
	pk := JwtConfig().PublicKey

	if !JwtConfig().EnableJwe {
		return access, refresh
	}

	ajwe, err := jwe.NewJWE(jwe.KeyAlgorithmRSAOAEP, pk, jwe.EncryptionTypeA256GCM, []byte(access))
	if err != nil {
		return access, refresh
	}
	atoken, err := ajwe.CompactSerialize()
	if err != nil {
		return access, refresh
	}

	rjwe, err := jwe.NewJWE(jwe.KeyAlgorithmRSAOAEP, pk, jwe.EncryptionTypeA256GCM, []byte(refresh))
	if err != nil {
		return access, refresh
	}
	rtoken, err := rjwe.CompactSerialize()
	if err != nil {
		return access, refresh
	}

	return atoken, rtoken

}

func CookieSetTokens(w http.ResponseWriter, a string, r string) {
	atoken, rtoken := encryptOrSkip(a, r)

	access := &http.Cookie{
		Name:     "access_token",
		Value:    atoken,
		Expires:  time.Now().Add(JwtConfig().AccessExpiry),
		Secure:   JwtConfig().SecureCookie,
		HttpOnly: JwtConfig().SecureCookie,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, access)

	refresh := &http.Cookie{
		Name:     "refresh_token",
		Value:    rtoken,
		Expires:  time.Now().Add(JwtConfig().RefreshExpiry),
		Secure:   JwtConfig().SecureCookie,
		HttpOnly: JwtConfig().SecureCookie,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	}

	http.SetCookie(w, refresh)
}

func CookieDecryptJwt(r *http.Request) (string, string, error) {
	c := JwtConfig()
	pk := c.PrivateKey

	access, err := r.Cookie("access_token")
	if err != nil {
		return "", "", err
	}

	refresh, err := r.Cookie("refresh_token")
	if err != nil {
		return "", "", err
	}

	if !c.EnableJwe {
		return access.Value, refresh.Value, nil
	}

	if c.PrivateKey == nil || c.PublicKey == nil {
		return "", "", ErrImpossible
	}

	ajwe, err := jwe.ParseEncrypted(access.Value)
	if err != nil {
		return "", "", err
	}

	at, err := ajwe.Decrypt(pk)
	if err != nil {
		return "", "", err
	}

	rjwe, err := jwe.ParseEncrypted(refresh.Value)
	if err != nil {
		return "", "", err
	}

	rt, err := rjwe.Decrypt(pk)
	if err != nil {
		return "", "", err
	}

	return string(at), string(rt), nil
}

func CookieDelete(w http.ResponseWriter, name string) {
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

func CookieRefreshOrDelete(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	access, refresh, err := CookieDecryptJwt(r)
	if err != nil {

	}

	vAccess, vRefresh, err := ParseOrRefreshToken(access, refresh)

	if err != nil {
		CookieDelete(w, "access_token")
		CookieDelete(w, "refresh_token")
		return "", "", false
	}

	if vAccess != access || vRefresh != refresh {
		CookieSetTokens(w, vAccess, vRefresh)
		return vAccess, vRefresh, true
	}

	return vAccess, vRefresh, true
}
