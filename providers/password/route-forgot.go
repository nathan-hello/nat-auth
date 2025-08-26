package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/providers/totp"
	"github.com/nathan-hello/nat-auth/utils"
	"github.com/nathan-hello/nat-auth/web"
)

func (p PasswordHandler) HandlerForgot(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		p.Forgot_GET(w, r)
		return
	}
	if r.Method == "POST" {
		p.Forgot_POST(w, r)
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (p PasswordHandler) Forgot_GET(w http.ResponseWriter, r *http.Request) {
	w.Write(p.Ui.HtmlPageForgot(r, AuthFormState{}))
}

func (p PasswordHandler) Forgot_POST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(400)
		w.Write(p.Ui.HtmlPageForgot(r, AuthFormState{Errors: []error{err}}))
		utils.Log("forgot-handler").Error("error parsing form: %#v", err.Error())
		return
	}
	username := r.FormValue("username")
	code := r.FormValue("code")

	subject, err := p.Database.SelectSubjectByUsername(username)
	if err != nil {
		utils.Log("forgot-handler").Error("error selecting subject: %#v", err.Error())
		w.Write(p.Ui.HtmlPageForgot(r, AuthFormState{Errors: []error{err}}))
		return
	}

	secret, err := p.Database.SelectSecret(subject)
	if err != nil {
		utils.Log("forgot-handler").Error("error selecting secret: %#v", err.Error())
		w.Write(p.Ui.HtmlPageForgot(r, AuthFormState{Errors: []error{err}}))
		return
	}

	err = totp.CheckTOTP(code, secret)
	if err != nil {
		utils.Log("forgot-handler").Error("error checking TOTP: %#v", err.Error())
		w.Write(p.Ui.HtmlPageForgot(r, AuthFormState{Errors: []error{web.ErrTOTPMismatch}}))
		return
	}

	access, refresh, _, err := web.NewTokenPair(web.JwtParams{Subject: subject, UserName: username})
	if err != nil {
		utils.Log("forgot-handler").Error("error creating token pair: %#v", err.Error())
		w.Write(p.Ui.HtmlPageForgot(r, AuthFormState{Errors: []error{err}}))
		return
	}

	web.CookieSetTokens(w, access, refresh)

	// if p.Callbacks.SuccessTotp != nil {
	// 	p.Callbacks.SuccessTotp(r, FormState{})
	// }

	web.HttpRedirect(w, r, p.Redirects.AfterSignIn, "/")
}
