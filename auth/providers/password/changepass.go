package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/logger"
	"golang.org/x/crypto/bcrypt"
)

func (p PasswordHandler) ChangePassHandler(w http.ResponseWriter, r *http.Request) {
	userId := auth.GetUserId(r)
	if !userId.Valid {
		logger.Log("ChangePassHandler").Error("User context invalid: %#v", userId)
		HttpRedirect(w, r, p.Redirects.AfterSignOut, "/")
		return
	}

	if r.Method == "GET" {
		if done := HttpRedirect(w, r, p.Redirects.BeforeChange, ""); done {
			return
		}
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
	w.Write(p.Ui.HtmlPageChange(r, FormState{}))
}

func (p PasswordHandler) ChangePass_POST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.Write(p.Ui.HtmlPageChange(r, FormState{Errors: ErrInternalServer}))
		return
	}

	password := r.FormValue("password")
	repeated := r.FormValue("repeated")

	err := p.ChangePass_Work(auth.GetUserId(r).Username, password, repeated)
	if err > 0 {
		w.Write(p.Ui.HtmlPageChange(r, FormState{Errors: err}))
		return
	}

	HttpRedirect(w, r, p.Redirects.AfterChange, "/")
}

func (p PasswordHandler) ChangePass_Work(username, password, repeated string) BitError {
	var errs BitError

	errs = errs.Add(passwordValidate(password))
	if errs > 0 {
		return errs
	}
	if password != repeated {
		return ErrPassNoMatch
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logger.Log("post-changepass").Error("could not generate hash from password: %s, error: %#v", password, err)
		return ErrHashPassword
	}

	err = p.Database.InsertUser(username, string(hashedPassword))
	if err != nil {
		logger.Log("post-changepass").Error("user: %s, pass: %s", username, hashedPassword)
		logger.Log("post-changepass").Error("could not insert user: %s, error: %#v", username, err.Error())
		return ErrDbInsertUser
	}

	return 0
}
