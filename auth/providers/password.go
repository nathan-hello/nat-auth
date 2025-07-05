package providers

import (
	"bytes"
	"net/http"
	"regexp"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/auth/components"
	"github.com/nathan-hello/nat-auth/auth/problems"
	"github.com/nathan-hello/nat-auth/httpwr"
	"github.com/nathan-hello/nat-auth/storage"
	"github.com/nathan-hello/nat-auth/utils"
	"golang.org/x/crypto/bcrypt"
)

type FormState struct {
	Username string
	Problems problems.BitError
}

type PasswordUi struct {
	HtmlPageSignUp func(*http.Request) []byte
	HtmlFormSignUp func(*http.Request, FormState) []byte
	HtmlPageSignIn func(*http.Request) []byte
	HtmlFormSignIn func(*http.Request, FormState) []byte
}

var PasswordUiDefault = PasswordUi{
	HtmlPageSignUp: func(r *http.Request) []byte {
		var buf bytes.Buffer
		components.SignUp("", 0).Render(r.Context(), &buf)
		return buf.Bytes()
	},
	HtmlFormSignUp: func(r *http.Request, state FormState) []byte {
		var buf bytes.Buffer
		components.SignUpForm(state.Username, state.Problems).Render(r.Context(), &buf)
		return buf.Bytes()
	},
	HtmlPageSignIn: func(r *http.Request) []byte {
		var buf bytes.Buffer
		components.SignIn("", 0).Render(r.Context(), &buf)
		return buf.Bytes()
	},
	HtmlFormSignIn: func(r *http.Request, state FormState) []byte {
		var buf bytes.Buffer
		components.SignInForm(state.Username, state.Problems).Render(r.Context(), &buf)
		return buf.Bytes()
	},
}

type PasswordHandler struct {
	UsernameValidate    func(s string) problems.BitError
	Database            storage.DbPassword
	RedirectAfterSignUp func(*http.Request) string
	RedirectAfterSignIn func(*http.Request) string
	Ui                  PasswordUi
}

func (p PasswordHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Write(p.Ui.HtmlPageSignUp(r))
		return
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(400)
			utils.Log("register-handler").Error("%#v", err)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")
		repeated := r.FormValue("repeated")

		params, errs := p.postRegister(username, password, repeated) // Work gets done here
		if errs.Count() > 0 {
			utils.Log("register-handler").Error("postRegister failed: %#v", errs.RenderMessages())
			w.Write(p.Ui.HtmlFormSignUp(r, FormState{Username: username, Problems: errs}))
			return
		}
		if params == nil {
			utils.Log("register-handler").Error("params is nil, this should never happen")
			w.Write(p.Ui.HtmlFormSignUp(r, FormState{Username: username, Problems: problems.ErrInternalServer}))
			return
		}

		access, refresh, err := auth.NewTokenPair(*params)
		if err != nil {
			utils.Log("register-handler").Error("could not create token pair: %#v", err)
			w.Write(p.Ui.HtmlFormSignUp(r, FormState{Username: username, Problems: problems.ErrParsingJwt}))
			return
		}
		httpwr.SetTokenCookies(w, access, refresh)

		redirect := p.RedirectAfterSignUp(r)
		w.Header().Set("HX-Redirect", redirect)
		return
	}

}

func (p PasswordHandler) postRegister(username, password, repeat string) (*auth.JwtParams, problems.BitError) {
	var errs problems.BitError
	if p.UsernameValidate == nil {
		p.UsernameValidate = defaultUsernameValidate
	}

	errs = errs.Add(p.UsernameValidate(username))
	errs = errs.Add(passwordValidate(password))
	if password != repeat {
		errs = errs.Add(problems.ErrPassNoMatch)
	}
	if errs.Count() > 0 {
		return nil, errs
	}

	// Does username already exist?
	_, err := p.Database.SelectSubjectByUsername(username)
	if err == nil {
		utils.Log("post-register").Error("username already exists: %s", username)
		errs = errs.Add(problems.ErrUsernameTaken)
		return nil, errs
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		utils.Log("post-register").Error("could not generate hash from password: %s, error: %#v", password, err)
		errs = errs.Add(problems.ErrHashPassword)
		return nil, errs
	}

	subject, err := utils.NewUUID()
	if err != nil {
		utils.Log("post-register").Error("could not generate uuid: %#v", err)
		errs = errs.Add(problems.ErrUuidFailed)
		return nil, errs
	}

	err = p.Database.InsertUser(username, string(hashedPassword), subject)
	if err != nil {
		utils.Log("post-register").Error("could not insert user: %s, error: %#v", username, err.Error())
		errs = errs.Add(problems.ErrDbInsertUser)
		return nil, errs
	}

	params := &auth.JwtParams{
		UserId: subject,
	}

	return params, errs
}

func (p PasswordHandler) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Write(p.Ui.HtmlPageSignIn(r))
		return
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			w.Write(p.Ui.HtmlFormSignIn(r, FormState{Problems: problems.ErrDbConnection}))
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")

		dbPassword, err := p.Database.SelectPasswordByUsername(username)
		if err != nil {
			utils.Log("authorize-handler").Error("could not select password by username: %s, error: %#v", username, err)
			w.Write(p.Ui.HtmlFormSignIn(r, FormState{Username: username, Problems: problems.ErrBadLogin}))
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(dbPassword), []byte(password))
		if err != nil {
			utils.Log("authorize-handler").Error("hash and password do not match: %s, error: %#v", username, err)
			w.Write(p.Ui.HtmlFormSignIn(r, FormState{Username: username, Problems: problems.ErrBadLogin}))
			return
		}

		subject, err := p.Database.SelectSubjectByUsername(username)
		if err != nil {
			utils.Log("authorize-handler").Error("could not select subject by username: %s, error: %#v", username, err)
			w.Write(p.Ui.HtmlFormSignIn(r, FormState{Username: username, Problems: problems.ErrDbSelectUserSubject}))
			return
		}

		access, refresh, err := auth.NewTokenPair(auth.JwtParams{UserId: subject})
		if err != nil {
			utils.Log("authorize-handler").Error("could not create token pair: %s, error: %#v", username, err)
			w.Write(p.Ui.HtmlFormSignIn(r, FormState{Username: username, Problems: problems.ErrParsingJwt}))
			return
		}
		httpwr.SetTokenCookies(w, access, refresh)

		redirect := p.RedirectAfterSignIn(r)
		w.Header().Set("HX-Redirect", redirect)
		return
	}
}

func defaultUsernameValidate(username string) problems.BitError {
	var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	var errs problems.BitError

	username = utils.SanitizeInput(username)

	if len(username) < 3 {
		errs = errs.Add(problems.ErrUsernameTooShort)
	}
	if len(username) > 32 {
		errs = errs.Add(problems.ErrUsernameTooLong)
	}
	if !usernameRegex.MatchString(username) {
		errs = errs.Add(problems.ErrUsernameInvalidFormat)
	}

	return errs
}

func passwordValidate(password string) problems.BitError {
	var errs problems.BitError

	bits := []byte(password)

	if len(bits) < 6 {
		errs = errs.Add(problems.ErrPasswordTooShort)
		return errs
	}
	if len(bits) > 72 {
		errs = errs.Add(problems.ErrPasswordTooLong)
		return errs
	}

	return errs
}
