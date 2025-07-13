package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/web"
	"golang.org/x/crypto/bcrypt"
)

func (p PasswordHandler) HandlerSignIn(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if done := web.HttpRedirect(w, r, p.Redirects.BeforeSignIn, ""); done {
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
		w.Write(p.Ui.HtmlPageSignIn(r, FormState{Errors: []error{err}}))
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	access, refresh, err := p.SignIn_Work(username, password)
	if err != nil {
		w.Write(p.Ui.HtmlPageSignIn(r, FormState{Errors: []error{err}}))
		return
	}

	web.CookieSetTokens(w, access, refresh)

	web.HttpRedirect(w, r, p.Redirects.AfterSignIn, "/")
}

func (p PasswordHandler) SignIn_Work(username, password string) (string, string, error) {
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
		return "", "", err
	}

	access, refresh, family, err := web.NewTokenPair(web.JwtParams{Subject: subject, UserName: username})
	if err != nil {
		return "", "", err
	}

	err = p.Database.InsertFamily(subject, family, true)
	if err != nil {
		return "", "", err
	}

	return access, refresh, nil
}
