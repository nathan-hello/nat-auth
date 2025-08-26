package password

import (
	"regexp"
	"strings"

	"github.com/nathan-hello/nat-auth/web"
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

func defaultUsernameValidate(username string) []error {
	var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)
	var errs []error

	username = sanitizeInput(username)

	if len(username) < 3 {
		errs = append(errs, web.ErrUsernameTooShort)
	}
	if len(username) > 32 {
		errs = append(errs, web.ErrUsernameTooLong)
	}
	if !usernameRegex.MatchString(username) {
		errs = append(errs, web.ErrUsernameInvalidFormat)
	}

	return errs
}

func passwordValidate(password string) error {
	bits := []byte(password)

	if len(bits) < 6 {
		return web.ErrPasswordTooShort
	}
	if len(bits) > 72 {
		return web.ErrPasswordTooLong
	}

	return nil
}
