package password

import (
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

func (p PasswordHandler) SignInHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if done := HttpRedirect(w, r, p.Redirects.BeforeSignIn, ""); done {
			return
		}
		p.SignIn_GET(w, r)
		return
	}
	if r.Method == "POST" {
		p.SignIn_POST(w, r)
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (p PasswordHandler) SignIn_GET(w http.ResponseWriter, r *http.Request) {
	w.Write(p.Ui.HtmlPageSignIn(r, FormState{}))
}

func (p PasswordHandler) SignIn_POST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.Write(p.Ui.HtmlPageSignIn(r, FormState{Errors: ErrInternalServer}))
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	access, refresh, err := p.SignIn_Work(username, password)
	if err > 0 {
		w.Write(p.Ui.HtmlPageSignIn(r, FormState{Errors: err}))
		return
	}

	CookieSetTokens(w, access, refresh)

	HttpRedirect(w, r, p.Redirects.AfterSignIn, "/")
}

func (p PasswordHandler) SignIn_Work(username, password string) (string, string, BitError) {
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
