package password

import (
	"errors"
	"slices"
)

// User-facing errors
var (
	ErrUsernameTooShort      = errors.New("username: too short")
	ErrUsernameTooLong       = errors.New("username: too long")
	ErrUsernameInvalidFormat = errors.New("username: invalid format")
	ErrUsernameTaken         = errors.New("username: already taken")
	ErrPasswordTooShort      = errors.New("password: too short")
	ErrPasswordTooLong       = errors.New("password: too long")
	ErrPassNoMatch           = errors.New("password: does not match")
	ErrBadLogin              = errors.New("generic: bad login")
	ErrTOTPMismatch          = errors.New("TOTP: code mismatch")
	ErrInternalServer        = errors.New("generic: internal server error")
)

var passwordErrors = []error{
	ErrPasswordTooShort,
	ErrPasswordTooLong,
	ErrBadLogin,
}

var usernameErrors = []error{
	ErrUsernameTooShort,
	ErrUsernameTooLong,
	ErrUsernameInvalidFormat,
	ErrUsernameTaken,
}

var repeatedErrors = []error{
	ErrPassNoMatch,
}

var userErrors = []error{
	ErrUsernameTooShort,
	ErrUsernameTooLong,
	ErrUsernameInvalidFormat,
	ErrUsernameTaken,
	ErrPasswordTooShort,
	ErrPasswordTooLong,
	ErrPassNoMatch,
	ErrBadLogin,
	ErrTOTPMismatch,
}

func IsPasswordError(err error) bool {
	for _, e := range passwordErrors {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func IsUsernameError(err error) bool {
	for _, e := range usernameErrors {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func IsRepeatedError(err error) bool {
	for _, e := range repeatedErrors {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func IsUserError(err error) bool {
	for _, e := range userErrors {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func HasUserError(errs []error) bool {
	return slices.ContainsFunc(errs, func(err error) bool {
		return IsUserError(err)
	})
}

func HasPasswordError(errs []error) bool {
	return slices.ContainsFunc(errs, func(err error) bool {
		return IsPasswordError(err)
	})
}

func HasUsernameError(errs []error) bool {
	return slices.ContainsFunc(errs, func(err error) bool {
		return IsUsernameError(err)
	})
}

func HasRepeatedError(errs []error) bool {
	return slices.ContainsFunc(errs, func(err error) bool {
		return IsRepeatedError(err)
	})
}

func HasSystemError(errs []error) bool {
	return slices.ContainsFunc(errs, func(err error) bool {
		return !IsUserError(err)
	})
}
