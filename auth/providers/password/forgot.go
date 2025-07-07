package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/auth/providers/totp"
	"github.com/nathan-hello/nat-auth/logger"
)

func (p PasswordHandler) ForgotHandler(w http.ResponseWriter, r *http.Request) {
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
	w.Write(p.Ui.HtmlPageForgot(r, FormState{}))
}

func (p PasswordHandler) Forgot_POST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(400)
		w.Write(p.Ui.HtmlPageForgot(r, FormState{Errors: ErrInternalServer}))
		logger.Log("forgot-handler").Error("error parsing form: %#v", err.Error())
		return
	}
	username := r.FormValue("username")
	code := r.FormValue("code")

	subject, err := p.Database.SelectSubjectByUsername(username)
	if err != nil {
		logger.Log("forgot-handler").Error("error selecting subject: %#v", err.Error())
		w.Write(p.Ui.HtmlPageForgot(r, FormState{Errors: ErrInternalServer}))
		return
	}

	secret, err := p.Database.SelectSecret(subject)
	if err != nil {
		logger.Log("forgot-handler").Error("error selecting secret: %#v", err.Error())
		w.Write(p.Ui.HtmlPageForgot(r, FormState{Errors: ErrInternalServer}))
	}

	err = totp.CheckTOTP(code, secret)
	if err != nil {
		logger.Log("forgot-handler").Error("error checking TOTP: %#v", err.Error())
		w.Write(p.Ui.HtmlPageForgot(r, FormState{Errors: ErrTOTPMismatch}))
		return
	}

	access, refresh, _, err := NewTokenPair(JwtParams{Subject: subject, UserName: username})
	if err != nil {
		logger.Log("forgot-handler").Error("error creating token pair: %#v", err.Error())
		w.Write(p.Ui.HtmlPageForgot(r, FormState{Errors: ErrInternalServer}))
		return
	}

	CookieSetTokens(w, access, refresh)

	// if p.Callbacks.SuccessTotp != nil {
	// 	p.Callbacks.SuccessTotp(r, FormState{})
	// }

	HttpRedirect(w, r, func(r *http.Request) string { return "/auth/change" }, "/")
}
