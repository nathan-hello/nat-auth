package httpwr

import (
	"net/http"
	"time"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/utils"
)

func SetTokenCookies(w http.ResponseWriter, a string, r string) {

	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    a,
		Expires:  time.Now().Add(utils.LocalConfig().AccessExpiry),
		Secure:   utils.LocalConfig().SecureCookie,
		HttpOnly: utils.LocalConfig().SecureCookie,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    r,
		Expires:  time.Now().Add(utils.LocalConfig().RefreshExpiry),
		Secure:   utils.LocalConfig().SecureCookie,
		HttpOnly: utils.LocalConfig().SecureCookie,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	})
}

func GetJwtsFromCookie(r *http.Request) (string, string, error) {
	access, err := r.Cookie("access_token")
	if err != nil {
		return "", "", err
	}

	refresh, err := r.Cookie("refresh_token")
	if err != nil {
		return "", "", err
	}

	return access.Value, refresh.Value, nil
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

func Validate_Delete_Or_Refresh(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	access, err := r.Cookie("access_token")
	if err != nil {
		if err == http.ErrNoCookie {
			return "", "", false
		}
		DeleteCookie(w, "access_token")
		DeleteCookie(w, "refresh_token")
		return "", "", false
	}

	refresh, err := r.Cookie("refresh_token")
	if err != nil {
		if err == http.ErrNoCookie {
			return "", "", false
		}
		DeleteCookie(w, "access_token")
		DeleteCookie(w, "refresh_token")
		return "", "", false
	}

	vAccess, vRefresh, err := auth.ValidatePairOrRefresh(access.Value, refresh.Value)

	if err != nil {
		DeleteCookie(w, "access_token")
		DeleteCookie(w, "refresh_token")
		return "", "", false
	}

	if vAccess != access.Value || vRefresh != refresh.Value {
		SetTokenCookies(w, vAccess, vRefresh)
		return vAccess, vRefresh, true
	}

	return vAccess, vRefresh, true
}
