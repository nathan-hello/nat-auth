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
		logger.Log("forgot-handler").Error("%#v", err)
		return
	}
	username := r.FormValue("username")
	code := r.FormValue("code")

	subject, err := p.Database.SelectSubjectByUsername(username)
	if err != nil {
		logger.Log("forgot-handler").Error("%#v", err)
		return
	}

	secret, err := p.Database.SelectSecret(subject)
	if err != nil {
		logger.Log("forgot-handler").Error("%#v", err)
	}

	err = totp.CheckTOTP(secret, code)
	if err != nil {
		logger.Log("forgot-handler").Error("%#v", err)
		return
	}

	access, refresh, _, err := NewTokenPair(JwtParams{Subject: subject, UserName: username})
	if err != nil {
		logger.Log("forgot-handler").Error("%#v", err)
		return
	}

	CookieSetTokens(w, access, refresh)

	HttpRedirect(w, r, func(r *http.Request) string { return "/auth/change" }, "/")
}
