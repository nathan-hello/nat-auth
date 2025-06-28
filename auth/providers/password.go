package providers

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/nathan-hello/nat-auth/auth/err"
)

type Hasher interface {
	Hash(password []byte) []byte
	Verify(password []byte, compare []byte) bool
}

type PasswordConfig struct {
	PasswordValidate func(s string) bool
	UsernameValidate func(s string) bool
	Hasher           Hasher
}

type PasswordHandler struct {
	Config PasswordConfig
}

func (p *PasswordHandler) Register(w http.ResponseWriter, r *http.Request) ([]byte, []err.AuthError) {
	var buf []byte

	if err := r.ParseForm(); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write(buf)
		return buf, nil
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	if !p.Config.UsernameValidate(username) || !p.Config.PasswordValidate(password) {

		w.WriteHeader(http.StatusBadRequest)
		w.Write(buf)

		return
	}

	w.Write(buf)
	return buf, nil

}

func defaultUsernameValidate(username string) []err.AuthError {
	var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	var errs []err.AuthError

	username = sanitizeInput(username)

	if len(username) < 3 {
		errs = append(errs, err.ErrUsernameTooShort)
	}
	if len(username) > 32 {
		errs = append(errs, err.ErrUsernameTooLong)
	}
	if !usernameRegex.MatchString(username) {
		errs = append(errs, err.ErrUsernameInvalidFormat)
	}

	return errs
}

func sanitizeInput(input string) string {
	// Remove HTML tags and special characters
	input = strings.TrimSpace(input)
	input = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1 // Remove control characters
		}
		return r
	}, input)
	return input
}
