package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/httpwr"
	"github.com/nathan-hello/nat-auth/utils"
)

func (p PasswordHandler) SignOutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if done := httpwr.Redirect(w, r, p.Redirects.BeforeSignOut, ""); done {
			return
		}
		httpwr.DeleteCookie(w, "access_token")
		httpwr.DeleteCookie(w, "refresh_token")
		httpwr.Redirect(w, r, p.Redirects.AfterSignOut, "/")
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (p PasswordHandler) SignOutEverywhereHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if done := httpwr.Redirect(w, r, p.Redirects.BeforeSignOut, ""); done {
			return
		}
		subject := auth.GetUserId(r)
		err := p.Database.InvalidateUser(subject)
		if err != nil {
			utils.Log("signout").Error("SignOutEverywhereHandler: could not update db err: %#v err.Error(): %s", err, err.Error())
		}
		httpwr.DeleteCookie(w, "access_token")
		httpwr.DeleteCookie(w, "refresh_token")
		httpwr.Redirect(w, r, p.Redirects.AfterSignOut, "/")
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}
