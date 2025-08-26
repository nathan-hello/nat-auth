package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/utils"
	"github.com/nathan-hello/nat-auth/web"
	"golang.org/x/crypto/bcrypt"
)

func (p PasswordHandler) HandlerChange(w http.ResponseWriter, r *http.Request) {
	userId := auth.GetUser(r)
	if !userId.Valid {
		utils.Log("ChangePassHandler").Error("User context invalid: %#v", userId)
		web.HttpRedirect(w, r, p.Redirects.AfterSignOut, "/")
		return
	}

	if r.Method == "GET" {
		p.ChangePass_GET(w, r)
		return
	}
	if r.Method == "POST" {
		p.ChangePass_POST(w, r)
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (p PasswordHandler) ChangePass_GET(w http.ResponseWriter, r *http.Request) {
	w.Write(p.Ui.HtmlPageChange(r, AuthFormState{}))
}

func (p PasswordHandler) ChangePass_POST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.Write(p.Ui.HtmlPageChange(r, AuthFormState{Errors: []error{err}}))
		return
	}

	password := r.FormValue("password")
	repeated := r.FormValue("repeated")

	err := p.ChangePass_Work(auth.GetUser(r).Username, password, repeated)
	if err != nil {
		w.Write(p.Ui.HtmlPageChange(r, AuthFormState{Errors: []error{err}}))
		return
	}

	web.HttpRedirect(w, r, p.Redirects.AfterSignIn, "/")
}

func (p PasswordHandler) ChangePass_Work(username, password, repeated string) error {
	err := passwordValidate(password)
	if err != nil {
		return err
	}
	if password != repeated {
		return web.ErrPassNoMatch
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		utils.Log("post-changepass").Error("could not generate hash from password: %s, error: %#v", password, err)
		return err
	}

	err = p.Database.InsertUser(username, string(hashedPassword))
	if err != nil {
		utils.Log("post-changepass").Error("could not insert user: %s, error: %#v", username, err.Error())
		return err
	}

	return nil
}
