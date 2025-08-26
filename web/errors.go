package web

import (
	"errors"
	"slices"
)

// System errors
var (
	ErrHashPassword        = errors.New("password hashing failed")
	ErrDbInsertUser        = errors.New("failed to insert user")
	ErrParsingJwt          = errors.New("failed to parse JWT")
	ErrJwtMethodBad        = errors.New("invalid JWT signing method")
	ErrJwtInvalid          = errors.New("JWT not found in database")
	ErrJwtInvalidInDb      = errors.New("JWT marked as invalid in database")
	ErrDbInsertToken       = errors.New("failed to insert token")
	ErrJwtGoodAccBadRef    = errors.New("access token was good but refresh was bad")
	ErrDbSelectUserSubject = errors.New("failed to select user subject")
	ErrUuidFailed          = errors.New("failed to generate UUID")
	ErrImpossible          = errors.New("this should be an impossible state")
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
	ErrTotpNotFound          = errors.New("TOTP: could not find user info")
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

var totpErrors = []error{
	ErrTotpNotFound,
}

func IsTotpError(err error) bool {
	for _, e := range totpErrors {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
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

func HasTotpError(errs []error) bool {
	return slices.ContainsFunc(errs, func(err error) bool {
		return IsTotpError(err)
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
