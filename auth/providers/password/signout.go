package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/auth/user"
	"github.com/nathan-hello/nat-auth/logger"
)

func (p PasswordHandler) SignOutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if done := HttpRedirect(w, r, p.Redirects.BeforeSignOut, ""); done {
			return
		}
		CookieDelete(w, "access_token")
		CookieDelete(w, "refresh_token")
		HttpRedirect(w, r, p.Redirects.AfterSignOut, "/")
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (p PasswordHandler) SignOutEverywhereHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if done := HttpRedirect(w, r, p.Redirects.BeforeSignOut, ""); done {
			return
		}
		Ctx := user.GetUser(r)
		err := p.Database.InvalidateUser(Ctx.Subject)
		if err != nil {
			logger.Log("signout").Error("SignOutEverywhereHandler: could not update db err: %#v err.Error(): %s", err, err.Error())
		}
		CookieDelete(w, "access_token")
		CookieDelete(w, "refresh_token")
		HttpRedirect(w, r, p.Redirects.AfterSignOut, "/")
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}
