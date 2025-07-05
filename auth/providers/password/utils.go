package password

import (
	"regexp"
	"strings"
)

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

func defaultUsernameValidate(username string) BitError {
	var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	var errs BitError

	username = sanitizeInput(username)

	if len(username) < 3 {
		errs = errs.Add(ErrUsernameTooShort)
	}
	if len(username) > 32 {
		errs = errs.Add(ErrUsernameTooLong)
	}
	if !usernameRegex.MatchString(username) {
		errs = errs.Add(ErrUsernameInvalidFormat)
	}

	return errs
}

func passwordValidate(password string) BitError {
	var errs BitError

	bits := []byte(password)

	if len(bits) < 6 {
		errs = errs.Add(ErrPasswordTooShort)
		return errs
	}
	if len(bits) > 72 {
		errs = errs.Add(ErrPasswordTooLong)
		return errs
	}

	return errs
}
