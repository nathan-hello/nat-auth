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

	// System errors (32-63)
	ErrHashPassword          BitError = 1 << 32
	ErrDbInsertUser          BitError = 1 << 33
	ErrDbSelectAfterInsert   BitError = 1 << 34
	ErrParsingJwt            BitError = 1 << 35
	ErrInvalidToken          BitError = 1 << 36
	ErrJwtNotInHeader        BitError = 1 << 37
	ErrJwtInvalid            BitError = 1 << 38
	ErrJwtMethodBad          BitError = 1 << 39
	ErrJwtInvalidInDb        BitError = 1 << 40
	ErrDbConnection          BitError = 1 << 41
	ErrDbInsertToken         BitError = 1 << 42
	ErrDbSelectUserFromToken BitError = 1 << 43
	ErrJwtGoodAccBadRef      BitError = 1 << 44
	ErrDbInsertUsersToken    BitError = 1 << 45
	ErrDbSelectUserFromJwt   BitError = 1 << 46
	ErrDbUpdateTokensInvalid BitError = 1 << 47
	ErrDbSelectUserSubject   BitError = 1 << 48
	ErrUuidFailed            BitError = 1 << 49
)

var messages = map[BitError]string{
	ErrUsernameTooShort:      "invalid username: too short",
	ErrUsernameTooLong:       "invalid username: too long",
	ErrUsernameInvalidFormat: "invalid username: invalid format",
	ErrUsernameTaken:         "invalid username: already taken",
	ErrPasswordTooShort:      "invalid password: too short",
	ErrPasswordTooLong:       "invalid password: too long",
	ErrPassNoMatch:           "invalid password: does not match",
	ErrBadLogin:              "invalid username or password",
	ErrInternalServer:        "internal server error",

	ErrHashPassword:          "password hashing failed",
	ErrDbInsertUser:          "failed to insert user",
	ErrDbSelectAfterInsert:   "failed to select after insert",
	ErrParsingJwt:            "failed to parse JWT",
	ErrInvalidToken:          "invalid token",
	ErrJwtNotInHeader:        "JWT not found in header",
	ErrJwtInvalid:            "JWT not found in database",
	ErrJwtMethodBad:          "invalid JWT signing method",
	ErrJwtInvalidInDb:        "JWT marked as invalid in database",
	ErrDbConnection:          "database connection error",
	ErrDbInsertToken:         "failed to insert token",
	ErrDbSelectUserFromToken: "failed to select user from token",
	ErrJwtGoodAccBadRef:      "access token was good but refresh was bad",
	ErrDbInsertUsersToken:    "failed to insert users tokens",
	ErrDbSelectUserFromJwt:   "failed to select user from JWT",
	ErrDbUpdateTokensInvalid: "failed to update tokens invalid",
	ErrDbSelectUserSubject:   "failed to select user subject",
	ErrUuidFailed:            "failed to generate UUID",
}

var errorCategories = map[BitError]string{
	ErrUsernameTooShort:      "username",
	ErrUsernameTooLong:       "username",
	ErrUsernameInvalidFormat: "username",
	ErrUsernameTaken:         "username",
	ErrPasswordTooShort:      "password",
	ErrPasswordTooLong:       "password",
	ErrPassNoMatch:           "repeated",
	ErrBadLogin:              "password",
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

// RenderUserMessages returns all error messages as a slice
// If system error, then give generic message
func (e BitError) RenderUserMessages() []string {
	var renderedMessages []string
	for err := range messages {
		// If there is at least one internal server error,
		// then any user errors are likely system errors is disguise
		if err.GetSystemErrors() > 0 {
			return []string{ErrInternalServer.Error()}
		}

		if e.Has(err) {
			renderedMessages = append(renderedMessages, messages[err])
		}

	}
	return renderedMessages
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

func (e BitError) GetErrorsByCategory(category string) []BitError {
	var filtered []BitError
	for err, cat := range errorCategories {
		if e.Has(err) && cat == category {
			filtered = append(filtered, err)
		}
	}
	return filtered
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
