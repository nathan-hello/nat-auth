package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/utils"
	"github.com/nathan-hello/nat-auth/web"
	"golang.org/x/crypto/bcrypt"
)

func (p PasswordHandler) HandlerSignUp(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if done := web.HttpRedirect(w, r, p.Redirects.BeforeSignUp, ""); done {
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
	w.Write(p.Ui.HtmlPageSignUp(r, AuthFormState{}))
}

func (p PasswordHandler) SignUp_POST(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		w.WriteHeader(400)
		utils.Log("register-handler").Error("%#v", err)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	repeated := r.FormValue("repeated")

	access, refresh, errs := p.SignUp_Work(username, password, repeated)

	if len(errs) > 0 {
		utils.Log("register-handler").Error("postRegister failed: %#v", errs)
		w.Write(p.Ui.HtmlPageSignUp(r, AuthFormState{Username: username, Errors: errs}))
		return
	}

	web.CookieSetTokens(w, access, refresh)

	// TODO: introduce passwordhandler to Locations struct
	web.HttpRedirect(w, r, p.Redirects.AfterSignUp, "/auth/totp")
}

func (p PasswordHandler) SignUp_Work(username, password, repeated string) (string, string, []error) {
	var errs []error
	if p.UsernameValidate == nil {
		p.UsernameValidate = defaultUsernameValidate
	}

	errs = append(errs, p.UsernameValidate(username)...)
	err := passwordValidate(password)
	if err != nil {
		errs = append(errs, err)
	}
	if password != repeated {
		errs = append(errs, web.ErrPassNoMatch)
	}

	// Does username already exist?
	_, err = p.Database.SelectSubjectByUsername(username)
	if err == nil {
		utils.Log("post-register").Error("username already exists: %s", username)
		errs = append(errs, web.ErrUsernameTaken)
		return "", "", errs
	}

	// Return early if we have validation errors
	if len(errs) > 0 {
		return "", "", errs
	}

	// From here on, we just immediately return errors instead of building them up
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		utils.Log("post-register").Error("could not generate hash from password: %s, error: %#v", password, err)
		return "", "", []error{web.ErrHashPassword}
	}

	subject, err := p.Database.NewUserId()
	if err != nil {
		utils.Log("post-register").Error("could not generate uuid: %#v", err)
		return "", "", []error{web.ErrUuidFailed}
	}

	err = p.Database.InsertUser(username, string(hashedPassword))
	if err != nil {
		utils.Log("post-register").Error("could not insert user: %s, error: %#v", username, err.Error())
		return "", "", []error{web.ErrDbInsertUser}
	}

	err = p.Database.InsertSubject(username, subject)
	if err != nil {
		utils.Log("post-register").Error("could not insert user: %s, error: %#v", username, err.Error())
		return "", "", []error{web.ErrDbInsertUser}
	}

	access, refresh, family, err := web.NewTokenPair(web.JwtParams{Subject: subject, UserName: username})
	if err != nil {
		utils.Log("post-register").Error("could not create token pair: %#v", err)
		return "", "", []error{web.ErrParsingJwt}
	}

	err = p.Database.InsertFamily(subject, family, true)
	if err != nil {
		return "", "", []error{web.ErrDbInsertToken}
	}

	return access, refresh, nil
}
