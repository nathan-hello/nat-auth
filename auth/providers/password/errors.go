package password

import (
	"fmt"
)

type BitError uint64

const (
	// User-facing errors (0-31)
	ErrUsernameTooShort      BitError = 1 << 0
	ErrUsernameTooLong       BitError = 1 << 1
	ErrUsernameInvalidFormat BitError = 1 << 2
	ErrUsernameTaken         BitError = 1 << 3
	ErrPasswordTooShort      BitError = 1 << 4
	ErrPasswordTooLong       BitError = 1 << 5
	ErrPassNoMatch           BitError = 1 << 6
	ErrBadLogin              BitError = 1 << 7
	ErrInternalServer        BitError = 1 << 8
	ErrTOTPMismatch          BitError = 1 << 14

	// System errors (32-63)
	ErrHashPassword        BitError = 1 << 32
	ErrDbInsertUser        BitError = 1 << 33
	ErrParsingJwt          BitError = 1 << 35
	ErrJwtMethodBad        BitError = 1 << 39
	ErrJwtInvalid          BitError = 1 << 38
	ErrJwtInvalidInDb      BitError = 1 << 40
	ErrDbInsertToken       BitError = 1 << 42
	ErrJwtGoodAccBadRef    BitError = 1 << 44
	ErrDbSelectUserSubject BitError = 1 << 48
	ErrUuidFailed          BitError = 1 << 49
)

var messages = map[BitError]string{
	ErrUsernameTooShort:      "username: too short",
	ErrUsernameTooLong:       "username: too long",
	ErrUsernameInvalidFormat: "username: invalid format",
	ErrUsernameTaken:         "username: already taken",
	ErrPasswordTooShort:      "password: too short",
	ErrPasswordTooLong:       "password: too long",
	ErrPassNoMatch:           "password: does not match",
	ErrBadLogin:              "generic: bad login",
	ErrInternalServer:        "generic: internal server error",
	ErrTOTPMismatch:          "TOTP: code mismatch",

	ErrHashPassword:        "password hashing failed",
	ErrDbInsertUser:        "failed to insert user",
	ErrParsingJwt:          "failed to parse JWT",
	ErrJwtMethodBad:        "invalid JWT signing method",
	ErrJwtInvalid:          "JWT not found in database",
	ErrJwtInvalidInDb:      "JWT marked as invalid in database",
	ErrDbInsertToken:       "failed to insert token",
	ErrJwtGoodAccBadRef:    "access token was good but refresh was bad",
	ErrDbSelectUserSubject: "failed to select user subject",
	ErrUuidFailed:          "failed to generate UUID",
}

var passwordErrors = []BitError{
	ErrPasswordTooShort,
	ErrPasswordTooLong,
	ErrBadLogin,
}

var usernameErrors = []BitError{
	ErrUsernameTooShort,
	ErrUsernameTooLong,
	ErrUsernameInvalidFormat,
	ErrUsernameTaken,
}

var repeatedErrors = []BitError{
	ErrPassNoMatch,
}

func (e BitError) Has(err BitError) bool {
	return (e & err) != 0
}

func (e BitError) Add(err BitError) BitError {
	return e | err
}

func (e BitError) Count() int {
	count := 0
	for i := 0; i < 64; i++ {
		if (e & (1 << i)) != 0 {
			count++
		}
	}
	return count
}

func (e BitError) GetErrors() []error {
	var errs []error
	for i := 0; i < 64; i++ {
		err := BitError(1 << i)
		if e.Has(err) {
			errs = append(errs, err)
		}
	}
	return errs
}

func (e BitError) RenderFullMessages() []string {
	var renderedMessages []string
	for err := range messages {
		if e.Has(err) {
			renderedMessages = append(renderedMessages, messages[err])
		}
	}
	return renderedMessages
}

func (e BitError) GetUserErrors() BitError {
	userErrors := BitError(0x00000000FFFFFFFF) // Bits 0-31 (user errors)
	return e & userErrors
}

func (e BitError) GetSystemErrors() BitError {
	systemErrors := BitError(0xFFFFFFFF00000000) // Bits 32-63 (system errors)
	return e & systemErrors
}

func (e BitError) Error() string {
	if e == 0 {
		return ""
	}

	messages := e.RenderFullMessages()
	if len(messages) == 1 {
		return messages[0]
	}

	return fmt.Sprintf("%v", messages)
}

func (e BitError) IsPasswordError() bool {
	for _, err := range passwordErrors {
		if e.Has(err) {
			return true
		}
	}
	return false
}

func (e BitError) IsUsernameError() bool {
	for _, err := range usernameErrors {
		if e.Has(err) {
			return true
		}
	}
	return false
}

func (e BitError) IsRepeatedError() bool {
	for _, err := range repeatedErrors {
		if e.Has(err) {
			return true
		}
	}
	return false
}
