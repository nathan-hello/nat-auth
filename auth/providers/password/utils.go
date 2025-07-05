package password

import (
	"regexp"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/utils"
)

func defaultUsernameValidate(username string) auth.BitError {
	var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	var errs auth.BitError

	username = utils.SanitizeInput(username)

	if len(username) < 3 {
		errs = errs.Add(auth.ErrUsernameTooShort)
	}
	if len(username) > 32 {
		errs = errs.Add(auth.ErrUsernameTooLong)
	}
	if !usernameRegex.MatchString(username) {
		errs = errs.Add(auth.ErrUsernameInvalidFormat)
	}

	return errs
}

func passwordValidate(password string) auth.BitError {
	var errs auth.BitError

	bits := []byte(password)

	if len(bits) < 6 {
		errs = errs.Add(auth.ErrPasswordTooShort)
		return errs
	}
	if len(bits) > 72 {
		errs = errs.Add(auth.ErrPasswordTooLong)
		return errs
	}

	return errs
}
