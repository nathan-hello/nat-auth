package providers

import (
	"net/http"
	"regexp"

	"github.com/nathan-hello/nat-auth/auth/problems"
	"github.com/nathan-hello/nat-auth/storage"
	"github.com/nathan-hello/nat-auth/utils"
)

type Hasher interface {
	Hash(password []byte) []byte
	Verify(password []byte, compare []byte) bool
}

type PasswordConfig struct {
	PasswordValidate func(s string) []problems.AuthError
	UsernameValidate func(s string) []problems.AuthError
	Storage          storage.StorageAdapter
	Hasher           Hasher
}

type PasswordHandler struct {
	Config PasswordConfig
}

// /register
func (p *PasswordHandler) Register(r *http.Request) []problems.AuthError {
	var errs []problems.AuthError

	if err := r.ParseForm(); err != nil {
		return errs
	}

	username := r.FormValue("username")
	password := r.FormValue("password")
	repeat := r.FormValue("repeat")

	errs = append(errs, p.Config.UsernameValidate(username)...)
	errs = append(errs, p.Config.PasswordValidate(password)...)
	if password != repeat {
		errs = append(errs, problems.ErrPassNoMatch)
	}
	if len(errs) > 0 {
		return errs
	}

	enc := p.Config.Hasher.Hash([]byte(password))

	return nil

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
