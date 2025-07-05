package httpwr

import (
	"net/http"
	"time"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/utils"
)

func SetTokenCookies(w http.ResponseWriter, a string, r string) {

	access := &http.Cookie{
		Name:     "access_token",
		Value:    a,
		Expires:  time.Now().Add(utils.LocalConfig().AccessExpiry),
		Secure:   utils.LocalConfig().SecureCookie,
		HttpOnly: utils.LocalConfig().SecureCookie,
		Path:     "/",
		SameSite: http.SameSiteLaxMode,
	}

	http.SetCookie(w, access)

	refresh := &http.Cookie{
		Name:     "refresh_token",
		Value:    r,
		Expires:  time.Now().Add(utils.LocalConfig().RefreshExpiry),
		Secure:   utils.LocalConfig().SecureCookie,
		HttpOnly: utils.LocalConfig().SecureCookie,
		Path:     "/",
		SameSite: http.SameSiteStrictMode,
	}

	http.SetCookie(w, refresh)
}

// Error is ignored because the only errors is ErrNoCookie.
// Which isn't an error state for us because refresh can exist
// longer than access. If both end up being empty strings, that's
// fine because the rest of the jwt stuff will catch it.
func GetJwtsFromCookie(r *http.Request) (string, string) {
	access, _ := r.Cookie("access_token")
	refresh, _ := r.Cookie("refresh_token")
	return access.Value, refresh.Value
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

func ValidateRefreshOrDeleteTokenFromCookies(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	access, refresh := GetJwtsFromCookie(r)

	vAccess, vRefresh, err := auth.ValidateOrRefreshToken(access, refresh)

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
