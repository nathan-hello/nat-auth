package problems

import (
	"fmt"
)

type BitError uint64

const (
	// User-facing errors (0-31)
	ErrUsernameTooShort      BitError = 1 << 0 // 1
	ErrUsernameTooLong       BitError = 1 << 1 // 2
	ErrUsernameInvalidFormat BitError = 1 << 2 // 4
	ErrUsernameTaken         BitError = 1 << 3 // 8
	ErrPasswordTooShort      BitError = 1 << 4 // 16
	ErrPasswordTooLong       BitError = 1 << 5 // 32
	ErrPassNoMatch           BitError = 1 << 6 // 64
	ErrBadLogin              BitError = 1 << 7 // 128
	ErrInternalServer        BitError = 1 << 8 // 256

	// System errors (32-63)
	ErrHashPassword          BitError = 1 << 32 // 65536
	ErrDbInsertUser          BitError = 1 << 33 // 131072
	ErrDbSelectAfterInsert   BitError = 1 << 34 // 262144
	ErrParsingJwt            BitError = 1 << 35 // 524288
	ErrInvalidToken          BitError = 1 << 36 // 1048576
	ErrJwtNotInHeader        BitError = 1 << 37 // 2097152
	ErrJwtNotInDb            BitError = 1 << 38 // 4194304
	ErrJwtMethodBad          BitError = 1 << 39 // 8388608
	ErrJwtInvalidInDb        BitError = 1 << 40 // 16777216
	ErrDbConnection          BitError = 1 << 41 // 33554432
	ErrDbInsertToken         BitError = 1 << 42 // 67108864
	ErrDbSelectUserFromToken BitError = 1 << 43 // 134217728
	ErrJwtGoodAccBadRef      BitError = 1 << 44 // 268435456
	ErrDbInsertUsersToken    BitError = 1 << 45 // 536870912
	ErrDbSelectUserFromJwt   BitError = 1 << 46 // 1073741824
	ErrDbUpdateTokensInvalid BitError = 1 << 47 // 2147483648
	ErrDbSelectUserSubject   BitError = 1 << 48 // 4294967296
	ErrUuidFailed            BitError = 1 << 49 // 8589934592
)

var messages = map[BitError]string{
	ErrUsernameTooShort:      "invalid username: too short",
	ErrUsernameTooLong:       "invalid username: too long",
	ErrUsernameInvalidFormat: "invalid username: invalid format",
	ErrUsernameTaken:         "username is already taken",
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
	ErrJwtNotInDb:            "JWT not found in database",
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

// Has checks if the error collection contains a specific error
func (e BitError) Has(err BitError) bool {
	return (e & err) != 0
}

// Add combines this error with another error
func (e BitError) Add(err BitError) BitError {
	return e | err
}

// Remove removes a specific error from the collection
func (e BitError) Remove(err BitError) BitError {
	return e &^ err
}

// IsEmpty checks if there are no errors
func (e BitError) IsEmpty() bool {
	return e == 0
}

// Count returns the number of errors in the collection
func (e BitError) Count() int {
	count := 0
	for i := 0; i < 64; i++ {
		if (e & (1 << i)) != 0 {
			count++
		}
	}
	return count
}

// GetErrors returns all individual errors as a slice
func (e BitError) GetErrors() []BitError {
	var errs []BitError
	for i := 0; i < 64; i++ {
		err := BitError(1 << i)
		if e.Has(err) {
			errs = append(errs, err)
		}
	}
	return errs
}

// RenderUserMessages returns all error messages as a slice
func (e BitError) RenderUserMessages() []string {
	var renderedMessages []string
	for err := range messages {
		if err.GetSystemErrors() != 0 {
			return []string{ErrInternalServer.Error()}
		}

		if e.Has(err) {
			renderedMessages = append(renderedMessages, messages[err])
		}

	}
	return renderedMessages
}

func (e BitError) RenderMessages() []string {
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
	if e.IsEmpty() {
		return ""
	}

	messages := e.RenderMessages()
	if len(messages) == 1 {
		return messages[0]
	}

	return fmt.Sprintf("multiple errors: %v", messages)
}
