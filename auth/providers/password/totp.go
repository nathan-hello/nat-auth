package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/auth/providers/totp"
)

func (p PasswordHandler) TotpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if done := HttpRedirect(w, r, p.Redirects.BeforeTotp, ""); done {
			return
		}
		p.Totp_GET(w, r)
		return
	}
	if r.Method == "POST" {
		p.Totp_POST(w, r)
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (p PasswordHandler) Totp_GET(w http.ResponseWriter, r *http.Request) {
	secret, err := totp.GenerateSecret()
	if err != nil {
		w.Write(p.Ui.HtmlPageTotp(r, FormState{Errors: ErrInternalServer}, nil))
	}
	err = p.Database.InsertSecret(auth.GetUserId(r).Subject, secret)
	if err != nil {
		w.Write(p.Ui.HtmlPageTotp(r, FormState{Errors: ErrInternalServer}, nil))
	}

	png, err := totp.QRTOTP(secret)
	if err != nil {
		w.Write(p.Ui.HtmlPageTotp(r, FormState{Errors: ErrInternalServer}, nil))
	}
	w.Write(p.Ui.HtmlPageTotp(r, FormState{}, png))
}

func (p PasswordHandler) Totp_POST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.Write(p.Ui.HtmlPageTotp(r, FormState{Errors: ErrInternalServer}, nil))
		return
	}
	otp := r.FormValue("otp")

	secret, err := p.Database.SelectSecret(auth.GetUserId(r).Subject)
	if err != nil {
		w.Write(p.Ui.HtmlPageTotp(r, FormState{Errors: ErrInternalServer}, nil))
		return
	}

	if totp.CheckTOTP(otp, secret) != nil {
		w.Write(p.Ui.HtmlPageTotp(r, FormState{Errors: ErrInternalServer}, nil))
		return
	}

	HttpRedirect(w, r, p.Redirects.AfterTotp, "/")
}
