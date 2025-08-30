package totp

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/web"
)

func (p TotpHandler) HandlerTotp(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		p.totp_GET(w, r)
		return
	}
	if r.Method == "POST" {
		p.totp_POST(w, r)
		return
	}

	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (p TotpHandler) totp_GET(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if !user.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	secret, err := p.Database.SelectSecret(user.Subject)

	if err != nil || secret == "" {
		secret, err = GenerateSecret()
		if err != nil {
			w.Write(p.Ui.HtmlPageTotp(r, TotpFormState{Errors: []error{err}}, nil, "/", ""))
			return
		}
		err = p.Database.InsertSecret(user.Subject, secret)
		if err != nil {
			w.Write(p.Ui.HtmlPageTotp(r, TotpFormState{Errors: []error{err}}, nil, "/", ""))
			return
		}
	}

	qr, err := QRTOTP(secret, user.Username, p.Issuer)
	if err != nil {
		w.Write(p.Ui.HtmlPageTotp(r, TotpFormState{Errors: []error{err}}, nil, "/", ""))
		return
	}

	var redirectUrl string

	if p.Redirects.AfterTotpVerification != nil {
		redirectUrl = p.Redirects.AfterTotpVerification(r)
	} else {
		redirectUrl = "/"
	}

	w.Write(p.Ui.HtmlPageTotp(r, TotpFormState{}, qr, redirectUrl, secret))
}

func (p TotpHandler) totp_POST(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)

	if !user.Valid {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	secret, err := p.Database.SelectSecret(user.Subject)
	if err != nil {
		w.Write(p.Ui.HtmlPageTotp(r, TotpFormState{Errors: []error{web.ErrInternalServer}}, nil, "/", ""))
		return
	}

	qr, err := QRTOTP(secret, user.Username, p.Issuer)
	if err != nil {
		w.Write(p.Ui.HtmlPageTotp(r, TotpFormState{Errors: []error{web.ErrInternalServer}}, nil, "/", ""))
		return
	}

	if err := r.ParseForm(); err != nil {
		w.Write(p.Ui.HtmlPageTotp(r, TotpFormState{Errors: []error{web.ErrInternalServer}}, qr, "/", ""))
		return
	}


	action := r.FormValue("action")
	switch (action) {
	case "test":
		otp := r.FormValue("code")

		err := CheckTOTP(otp, secret) 
		if err != nil {
			w.Write(p.Ui.HtmlPageTotp(r, TotpFormState{Errors: []error{web.ErrTOTPMismatch}}, qr, "/", secret))
			return
		}

		w.Write(p.Ui.HtmlPageTotp(r, TotpFormState{Success: true}, qr, "/", secret))
		return
		

	case "skip":
		web.HttpRedirect(w, r, p.Redirects.AfterTotpSkip, "/")
		return

	case "reroll":
		secret, err := GenerateSecret()
		if err != nil {
			w.Write(p.Ui.HtmlPageTotp(r, TotpFormState{Errors: []error{err}}, nil, "/", ""))
			return
		}
		err = p.Database.InsertSecret(user.Subject, secret)
		if err != nil {
			w.Write(p.Ui.HtmlPageTotp(r, TotpFormState{Errors: []error{err}}, nil, "/", ""))
			return
		}

		http.Redirect(w, r, "/auth/totp", http.StatusSeeOther)
		return
	}

	w.WriteHeader(http.StatusBadRequest)

}
