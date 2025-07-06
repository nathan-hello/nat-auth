package password

import (
	"net/http"

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
		w.Write(p.Ui.HtmlFormTotp(r, FormState{Errors: ErrInternalServer}))
	}
	png, err := totp.QRTOTP(secret)
	w.Write(p.Ui.HtmlPageTotp(r, FormState{Username: png}))
}

func (p PasswordHandler) Totp_POST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.Write(p.Ui.HtmlFormTotp(r, FormState{Errors: ErrInternalServer}))
		return
	}
	otp := r.FormValue("otp")

	png, err := p.Totp_Work(otp)
	if err > 0 {
		w.Write(p.Ui.HtmlFormTotp(r, FormState{Username: png, Errors: err}))
		return
	}

	HttpRedirect(w, r, p.Redirects.AfterTotp, "/")
}

func (p PasswordHandler) Totp_Work(otp string) (string, BitError) {

}
