package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/providers/totp"
	"github.com/nathan-hello/nat-auth/web"
)

func (p PasswordHandler) HandlerTotp(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		p.Totp_GET(w, r)
		return
	}
	if r.Method == "POST" {
		p.Totp_POST(w, r)
		return
	}
	if r.Method == "PATCH" {
		p.Totp_PATCH(w, r)
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
}

// TODO: on patch, update secret in db
func (p PasswordHandler) Totp_PATCH(w http.ResponseWriter, r *http.Request) {

}

func (p PasswordHandler) Totp_GET(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if !user.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	secret, err := p.Database.SelectSecret(user.Subject)
	if err != nil || secret == "" {
		secret, err = totp.GenerateSecret()
		if err != nil {
			w.Write(p.Ui.HtmlPageTotp(r, FormState{Errors: []error{err}}, nil, "/", ""))
			return
		}
		err = p.Database.InsertSecret(user.Subject, secret)
		if err != nil {
			w.Write(p.Ui.HtmlPageTotp(r, FormState{Errors: []error{err}}, nil, "/", ""))
			return
		}
	}

	png, err := totp.QRTOTP(secret, user.Username)
	if err != nil {
		w.Write(p.Ui.HtmlPageTotp(r, FormState{Errors: []error{err}}, nil, "/", ""))
		return
	}

	var redirectUrl string

	if p.Redirects.AfterSignIn != nil {
		redirectUrl = p.Redirects.AfterSignIn(r)
	} else {
		redirectUrl = "/"
	}

	w.Write(p.Ui.HtmlPageTotp(r, FormState{}, png, redirectUrl, secret))
}

func (p PasswordHandler) Totp_POST(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if !user.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil {
		w.Write(p.Ui.HtmlPageTotp(r, FormState{Errors: []error{err}}, nil, "/", ""))
		return
	}
	otp := r.FormValue("code")

	secret, err := p.Database.SelectSecret(user.Subject)
	if err != nil {
		w.Write(p.Ui.HtmlPageTotp(r, FormState{Errors: []error{err}}, nil, "/", ""))
		return
	}

	if totp.CheckTOTP(otp, secret) != nil {
		w.Write(p.Ui.HtmlPageTotp(r, FormState{Errors: []error{ErrTOTPMismatch}}, nil, "/", ""))
		return
	}

	web.HttpRedirect(w, r, p.Redirects.AfterSignIn, "/")
}
