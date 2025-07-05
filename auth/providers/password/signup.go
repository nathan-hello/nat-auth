package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/httpwr"
	"github.com/nathan-hello/nat-auth/utils"
	"golang.org/x/crypto/bcrypt"
)

func (p PasswordHandler) SignUpHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {

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
	w.Write(p.Ui.HtmlPageSignUp(r))
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

	if errs > 0 {
		utils.Log("register-handler").Error("postRegister failed: %#v", errs.RenderUserMessages())
		w.Write(p.Ui.HtmlFormSignUp(r, FormState{Username: username, Errors: errs}))
		return
	}

	httpwr.SetTokenCookies(w, access, refresh)

	redirect := p.RedirectAfterSignUp(r)
	w.Header().Set("HX-Redirect", redirect)
}

func (p PasswordHandler) SignUp_Work(username, password, repeated string) (string, string, auth.BitError) {
	var errs auth.BitError
	if p.UsernameValidate == nil {
		p.UsernameValidate = defaultUsernameValidate
	}

	errs = errs.Add(p.UsernameValidate(username))
	errs = errs.Add(passwordValidate(password))
	if password != repeated {
		errs = errs.Add(auth.ErrPassNoMatch)
	}
	if errs.Count() > 0 {
		return "", "", errs
	}

	// Does username already exist?
	_, err := p.Database.SelectSubjectByUsername(username)
	if err == nil {
		utils.Log("post-register").Error("username already exists: %s", username)
		errs = errs.Add(auth.ErrUsernameTaken)
		return "", "", errs
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		utils.Log("post-register").Error("could not generate hash from password: %s, error: %#v", password, err)
		errs = errs.Add(auth.ErrHashPassword)
		return "", "", errs
	}

	subject, err := utils.NewUUID()
	if err != nil {
		utils.Log("post-register").Error("could not generate uuid: %#v", err)
		errs = errs.Add(auth.ErrUuidFailed)
		return "", "", errs
	}

	err = p.Database.InsertUser(username, string(hashedPassword), subject)
	if err != nil {
		utils.Log("post-register").Error("could not insert user: %s, error: %#v", username, err.Error())
		errs = errs.Add(auth.ErrDbInsertUser)
		return "", "", errs
	}

	access, refresh, err := auth.NewTokenPair(auth.JwtParams{UserId: subject})
	if err != nil {
		utils.Log("api-register").Error("could not create token pair: %#v", err)
		return "", "", auth.ErrParsingJwt
	}

	return access, refresh, errs
}
