package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/httpwr"
	"github.com/nathan-hello/nat-auth/utils"
	"golang.org/x/crypto/bcrypt"
)

func (p PasswordHandler) SignInHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
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

	redirect := p.RedirectAfterSignIn(r)
	w.Header().Set("HX-Redirect", redirect)
}

func (p PasswordHandler) SignIn_Work(username, password string) (string, string, auth.BitError) {
	dbPassword, err := p.Database.SelectPasswordByUsername(username)
	if err != nil {
		utils.Log("authorize-handler").Error("could not select password by username: %s, error: %#v", username, err)
		return "", "", auth.ErrBadLogin
	}

	err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
	if err != nil {
		utils.Log("authorize-handler").Error("hash and password do not match: %s, error: %#v", username, err)
		return "", "", auth.ErrBadLogin
	}

	subject, err := p.Database.SelectSubjectByUsername(username)
	if err != nil {
		utils.Log("authorize-handler").Error("could not select subject by username: %s, error: %#v", username, err)
		return "", "", auth.ErrDbSelectUserSubject
	}

	access, refresh, err := auth.NewTokenPair(auth.JwtParams{UserId: subject})
	if err != nil {
		utils.Log("authorize-handler").Error("could not create token pair: %s, error: %#v", username, err)
		return "", "", auth.ErrParsingJwt
	}

	return access, refresh, 0
}
