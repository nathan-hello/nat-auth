package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/httpwr"
	"golang.org/x/crypto/bcrypt"
)

func (p PasswordHandler) SignInHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if done := httpwr.Redirect(w, r, p.Redirects.BeforeSignIn, ""); done {
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
	w.Write(p.Ui.HtmlPageSignIn(r))
}

func (p PasswordHandler) SignIn_POST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.Write(p.Ui.HtmlFormSignIn(r, FormState{Errors: auth.ErrInternalServer}))
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	access, refresh, err := p.SignIn_Work(username, password)
	if err > 0 {
		w.Write(p.Ui.HtmlFormSignIn(r, FormState{Errors: err}))
		return
	}

	httpwr.SetTokenCookies(w, access, refresh)

	httpwr.Redirect(w, r, p.Redirects.AfterSignIn, "/")
}

func (p PasswordHandler) SignIn_Work(username, password string) (string, string, auth.BitError) {
	dbPassword, err := p.Database.SelectPasswordByUsername(username)
	if err != nil {
		return "", "", auth.ErrBadLogin
	}

	err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
	if err != nil {
		return "", "", auth.ErrBadLogin
	}

	subject, err := p.Database.SelectSubjectByUsername(username)
	if err != nil {
		return "", "", auth.ErrDbSelectUserSubject
	}

	access, refresh, family, err := auth.NewTokenPair(auth.JwtParams{UserId: subject})
	if err != nil {
		return "", "", auth.ErrParsingJwt
	}

	err = p.Database.InsertFamily(subject, family, true)
	if err != nil {
		return "", "", auth.ErrDbInsertToken
	}

	return access, refresh, 0
}
