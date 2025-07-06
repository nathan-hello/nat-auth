package password

import (
	"context"
	"net/http"
	"time"

	"github.com/golang-jwt/jwe"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/logger"
)

func CookieSetTokens(w http.ResponseWriter, a string, r string) {
	pk := LocalConfig().PublicKey

	var atoken string
	var rtoken string
	ajwe, err := jwe.NewJWE(jwe.KeyAlgorithmRSAOAEP, pk, jwe.EncryptionTypeA256GCM, []byte(a))
	if err == nil {
		atoken, err = ajwe.CompactSerialize()
		if err != nil {
			atoken = a
			logger.Log("cookie").Warn("access-token could not be serialized")
		}
	} else {
		atoken = a
		logger.Log("cookie").Warn("access-token was not encrypted")
	}
	rjwe, err := jwe.NewJWE(jwe.KeyAlgorithmRSAOAEP, pk, jwe.EncryptionTypeA256GCM, []byte(a))
	if err == nil {
		rtoken, err = rjwe.CompactSerialize()
		if err != nil {
			rtoken = a
			logger.Log("cookie").Warn("access-token could not be serialized")
		}
	} else {
		rtoken = a
		logger.Log("cookie").Warn("access-token was not encrypted")
	}

	access := &http.Cookie{
		Name:     "access_token",
		Value:    atoken,
		Expires:  time.Now().Add(LocalConfig().AccessExpiry),
		Secure:   LocalConfig().SecureCookie,
		HttpOnly: LocalConfig().SecureCookie,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, access)

	refresh := &http.Cookie{
		Name:     "refresh_token",
		Value:    rtoken,
		Expires:  time.Now().Add(LocalConfig().RefreshExpiry),
		Secure:   LocalConfig().SecureCookie,
		HttpOnly: LocalConfig().SecureCookie,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	}

	http.SetCookie(w, refresh)
}

func CookieDecryptJwt(r *http.Request) (string, string, error) {
	pk := LocalConfig().PrivateKey

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

func MiddlewareVerifyJwtAndInjectUserId(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access, _, ok := CookieRefreshOrDelete(w, r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		claims, err := ParseToken(access)
		if err != nil {
			logger.Log("middleware").Error("parsed claims %#v %s", claims, err)
			next.ServeHTTP(w, r)
			return
		}

		val := auth.AuthContext{
			Subject:  claims.Subject,
			Username: claims.UserName,
		}

		wrapReq := r.WithContext(context.WithValue(r.Context(), auth.AuthContextKey, val))
		next.ServeHTTP(w, wrapReq)
	})
}

func Redirect(w http.ResponseWriter, r *http.Request, redirectFunc func(r *http.Request) string, defaultRoute string) bool {
	if redirectFunc == nil {
		if defaultRoute == "" {
			return false
		}
		w.Header().Set("HX-Redirect", defaultRoute)
		return true
	}
	if route := redirectFunc(r); route != "" {
		w.Header().Set("HX-Redirect", route)
		return true
	}

	if defaultRoute != "" {
		w.Header().Set("HX-Redirect", defaultRoute)
		return true
	}

	return false

}
