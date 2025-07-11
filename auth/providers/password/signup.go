package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/logger"
	"golang.org/x/crypto/bcrypt"
)

func (p PasswordHandler) SignUpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if done := HttpRedirect(w, r, p.Redirects.BeforeSignUp, ""); done {
			return
		}
		p.SignUp_GET(w, r)
		return
	}
	if r.Method == "POST" {
		p.SignUp_POST(w, r)
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (p PasswordHandler) SignUp_GET(w http.ResponseWriter, r *http.Request) {
	w.Write(p.Ui.HtmlPageSignUp(r, FormState{}))
}

func (p PasswordHandler) SignUp_POST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(400)
		logger.Log("register-handler").Error("%#v", err)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	repeated := r.FormValue("repeated")

	access, refresh, errs := p.SignUp_Work(username, password, repeated)

	if errs > 0 {
		logger.Log("register-handler").Error("postRegister failed: %#v", errs.RenderFullMessages())
		w.Write(p.Ui.HtmlPageSignUp(r, FormState{Username: username, Errors: errs}))
		return
	}

	CookieSetTokens(w, access, refresh)

	HttpRedirect(w, r, p.Redirects.AfterSignUp, "/")
}

func (p PasswordHandler) SignUp_Work(username, password, repeated string) (string, string, BitError) {
	var errs BitError
	if p.UsernameValidate == nil {
		p.UsernameValidate = defaultUsernameValidate
	}

	errs = errs.Add(p.UsernameValidate(username))
	errs = errs.Add(passwordValidate(password))
	if password != repeated {
		return "", "", ErrPassNoMatch
	}

	// Does username already exist?
	_, err := p.Database.SelectSubjectByUsername(username)
	if err == nil {
		logger.Log("post-register").Error("username already exists: %s", username)
		errs = errs.Add(ErrUsernameTaken)
		return "", "", errs
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		logger.Log("post-register").Error("could not generate hash from password: %s, error: %#v", password, err)
		errs = errs.Add(ErrHashPassword)
		return "", "", errs
	}

	subject, err := p.Database.NewUserId()
	if err != nil {
		logger.Log("post-register").Error("could not generate uuid: %#v", err)
		errs = errs.Add(ErrUuidFailed)
		return "", "", errs
	}

	err = p.Database.InsertUser(username, string(hashedPassword))
	if err != nil {
		logger.Log("post-register").Error("could not insert user: %s, error: %#v", username, err.Error())
		errs = errs.Add(ErrDbInsertUser)
		return "", "", errs
	}

	err = p.Database.InsertSubject(username, subject)
	if err != nil {
		logger.Log("post-register").Error("could not insert user: %s, error: %#v", username, err.Error())
		errs = errs.Add(ErrDbInsertUser)
		return "", "", errs
	}

	access, refresh, family, err := NewTokenPair(JwtParams{Subject: subject, UserName: username})
	if err != nil {
		logger.Log("post-register").Error("could not create token pair: %#v", err)
		return "", "", ErrParsingJwt
	}

	err = p.Database.InsertFamily(subject, family, true)
	if err != nil {
		return "", "", ErrDbInsertToken
	}

	return access, refresh, errs
}
