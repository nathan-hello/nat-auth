package password

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"
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
	w.Write(p.Ui.HtmlPageTotp(r))
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
	dbPassword, err := p.Database.SelectPasswordByUsername(username)
	if err != nil {
		return "", "", ErrBadLogin
	}

	err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
	if err != nil {
		return "", "", ErrBadLogin
	}

	subject, err := p.Database.SelectSubjectByUsername(username)
	if err != nil {
		return "", "", ErrDbSelectUserSubject
	}

	access, refresh, family, err := NewTokenPair(JwtParams{Subject: subject, UserName: username})
	if err != nil {
		return "", "", ErrParsingJwt
	}

	err = p.Database.InsertFamily(subject, family, true)
	if err != nil {
		return "", "", ErrDbInsertToken
	}

	return access, refresh, 0
}
