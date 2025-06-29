package password

import (
	"crypto/rand"
	"net/http"
	"regexp"

	"github.com/google/uuid"
	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/auth/components"
	"github.com/nathan-hello/nat-auth/auth/problems"
	"github.com/nathan-hello/nat-auth/httpwr"
	"github.com/nathan-hello/nat-auth/storage"
	"github.com/nathan-hello/nat-auth/utils"
	"golang.org/x/crypto/bcrypt"
)

var PASSWORD_IDENTITY = "auth:userpw"

type PasswordConfig struct {
	UsernameValidate    func(s string) []problems.AuthError
	Storage             storage.StorageAdapter
	RedirectAfterSignUp string
	RedirectAfterSignIn string
}

type PasswordHandler struct {
	Config PasswordConfig
}

// POST /register
func (p *PasswordHandler) PostRegister(username, password, repeat string) (*auth.JwtParams, []problems.AuthError) {
	var errs []problems.AuthError
	if p.Config.UsernameValidate == nil {
		p.Config.UsernameValidate = defaultUsernameValidate
	}

	errs = append(errs, p.Config.UsernameValidate(username)...)
	errs = append(errs, passwordValidate(password)...)
	if password != repeat {
		errs = append(errs, problems.ErrPassNoMatch)
	}
	if len(errs) > 0 {
		return nil, errs
	}
	_, err := p.Config.Storage.Get([]string{PASSWORD_IDENTITY, "username", username, "password"})
	if err == nil {
		errs = append(errs, problems.ErrEmailTaken)
		return nil, errs
	}

	enc, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		errs = append(errs, problems.ErrHashPassword(err.Error()))
		return nil, errs
	}

	err = p.Config.Storage.Set([]string{PASSWORD_IDENTITY, "username", username, "password"}, enc)
	if err != nil {
		errs = append(errs, problems.ErrDbSelectAfterInsert(err.Error()))
		return nil, errs
	}

	subject, err := uuid.NewRandomFromReader(rand.Reader)
	if err != nil {
		errs = append(errs, problems.ErrUuidFailed(err.Error()))
		return nil, errs
	}

	err = p.Config.Storage.Set([]string{PASSWORD_IDENTITY, "username", username, "subject"}, []byte(subject.String()))
	if err != nil {
		errs = append(errs, problems.ErrDbInsertUser)
	}

	params := &auth.JwtParams{
		Username: username,
		UserId:   subject.String(),
	}

	return params, nil
}

func (p *PasswordHandler) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		components.SignUp("", nil).Render(r.Context(), w)
		return
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(400)
			return
		}

		username := r.FormValue("username")
		password := r.FormValue("password")
		repeat := r.FormValue("repeat")
		params, errs := p.PostRegister(username, password, repeat)
		if errs != nil {
			components.SignUpForm(username, errs).Render(r.Context(), w)
			return
		}
		access, refresh, err := auth.NewTokenPair(params)
		if err != nil {
			components.SignUpForm(username, []problems.AuthError{problems.NewSystemError(err)}).Render(r.Context(), w)
			return
		}
		httpwr.SetTokenCookies(w, access, refresh)

		w.Header().Set("HX-Redirect", p.Config.RedirectAfterSignUp)
		return
	}

}

func (p *PasswordHandler) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		components.SignIn("", nil).Render(r.Context(), w)
		return
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			components.SignInForm("", []problems.AuthError{problems.NewSystemError(err)}).Render(r.Context(), w)
			return
		}
		username := r.FormValue("username")
		password := r.FormValue("password")

		dbPassword, err := p.Config.Storage.Get([]string{PASSWORD_IDENTITY, "username", username, "password"})
		if err != nil {
			components.SignIn(username, []problems.AuthError{problems.ErrBadLogin})
			return
		}
		err = bcrypt.CompareHashAndPassword(dbPassword, []byte(password))
		if err != nil {
			components.SignIn(username, []problems.AuthError{problems.ErrBadLogin})
			return
		}

		subject, err := p.Config.Storage.Get([]string{PASSWORD_IDENTITY, "username", username, "subject"})
		if err != nil {
			components.SignIn(username, []problems.AuthError{problems.ErrDbSelectUserSubject})
			return
		}

		access, refresh, err := auth.NewTokenPair(&auth.JwtParams{Username: username, UserId: string(subject)})
		if err != nil {
			components.SignUpForm(username, []problems.AuthError{problems.NewSystemError(err)}).Render(r.Context(), w)
			return
		}
		httpwr.SetTokenCookies(w, access, refresh)

		w.Header().Set("HX-Redirect", p.Config.RedirectAfterSignIn)
		return
	}
}

func defaultUsernameValidate(username string) []problems.AuthError {
	var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	var errs []problems.AuthError

	username = utils.SanitizeInput(username)

	if len(username) < 3 {
		errs = append(errs, problems.ErrUsernameTooShort)
	}
	if len(username) > 32 {
		errs = append(errs, problems.ErrUsernameTooLong)
	}
	if !usernameRegex.MatchString(username) {
		errs = append(errs, problems.ErrUsernameInvalidFormat)
	}

	return errs
}

func passwordValidate(password string) []problems.AuthError {
	var errs []problems.AuthError

	bits := []byte(password)

	if len(bits) < 6 {
		errs = append(errs, problems.ErrPasswordTooShort)
		return errs
	}
	if len(bits) > 72 {
		errs = append(errs, problems.ErrPasswordTooLong)
		return errs
	}
	return nil
}
