package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/utils"
	"github.com/nathan-hello/nat-auth/web"
)

func (p PasswordHandler) HandlerSignOut(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if done := web.HttpRedirect(w, r, p.Redirects.BeforeSignOut, ""); done {
			return
		}
		web.CookieDelete(w, "access_token")
		web.CookieDelete(w, "refresh_token")
		web.HttpRedirect(w, r, p.Redirects.AfterSignOut, "/")
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (p PasswordHandler) HandlerSignOutEverywhere(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if done := web.HttpRedirect(w, r, p.Redirects.BeforeSignOut, ""); done {
			return
		}
		Ctx := auth.GetUser(r)
		err := p.Database.InvalidateUser(Ctx.Subject)
		if err != nil {
			utils.Log("signout").Error("SignOutEverywhereHandler: could not update db err: %#v err.Error(): %s", err, err.Error())
		}
		web.CookieDelete(w, "access_token")
		web.CookieDelete(w, "refresh_token")
		web.HttpRedirect(w, r, p.Redirects.AfterSignOut, "/")
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}
