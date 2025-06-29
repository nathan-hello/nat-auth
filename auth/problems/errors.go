package problems

import (
	"errors"
	"fmt"
)

type AuthError struct {
	Code     uint16
	Message  string // User-facing message
	Category string // Field or category (e.g. "username", "password", "system")
	Err      error
}

func (e AuthError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e AuthError) Unwrap() error {
	return e.Err
}

var (
	ErrUsernameTooShort = AuthError{
		Code:     1,
		Message:  "username must be at least 3 characters long",
		Category: "username",
	}
	ErrUsernameTooLong = AuthError{
		Code:     2,
		Message:  "username must be at most 30 characters long",
		Category: "username",
	}
	ErrUsernameInvalidFormat = AuthError{
		Code:     3,
		Message:  "username can only contain letters, numbers, underscores, and hyphens",
		Category: "username",
	}
	ErrEmailInvalid = AuthError{
		Code:     4,
		Message:  "invalid email format",
		Category: "email",
	}
	ErrEmailOrUsernameReq = AuthError{
		Code:     5,
		Message:  "email or username is required",
		Category: "username",
	}
	ErrEmailTaken = AuthError{
		Code:     6,
		Message:  "email is already taken",
		Category: "email",
	}
	ErrUsernameTaken = AuthError{
		Code:     7,
		Message:  "username is already taken",
		Category: "username",
	}
	ErrPasswordTooShort = AuthError{
		Code:     8,
		Message:  "password must be at least 8 characters long",
		Category: "password",
	}
	ErrPasswordTooLong = AuthError{
		Code:     8,
		Message:  "password must not be more than 72 characters long",
		Category: "password",
	}
	ErrPassNoMatch = AuthError{
		Code:     9,
		Message:  "passwords do not match",
		Category: "password",
	}
	ErrBadLogin = AuthError{
		Code:     10,
		Message:  "invalid username/email or password",
		Category: "login",
	}
)

// System errors that should not be exposed to users
var (
	ErrHashPassword = func(msg string) AuthError {
		return AuthError{
			Code:     1,
			Message:  msg,
			Category: "system",
		}
	}
	ErrDbInsertUser = AuthError{
		Code:     2,
		Message:  "failed to insert user",
		Category: "system",
	}
	ErrDbSelectAfterInsert = func(msg string) AuthError {
		return AuthError{
			Code:     3,
			Message:  msg,
			Category: "system",
		}
	}
	ErrParsingJwt = AuthError{
		Code:     4,
		Message:  "failed to parse JWT",
		Category: "system",
	}
	ErrInvalidToken = AuthError{
		Code:     5,
		Message:  "invalid token",
		Category: "system",
	}
	ErrJwtNotInHeader = AuthError{
		Code:     6,
		Message:  "JWT not found in header",
		Category: "system",
	}
	ErrJwtNotInDb = AuthError{
		Code:     7,
		Message:  "JWT not found in database",
		Category: "system",
	}
	ErrJwtMethodBad = AuthError{
		Code:     8,
		Message:  "invalid JWT signing method",
		Category: "system",
	}
	ErrJwtInvalidInDb = AuthError{
		Code:     9,
		Message:  "JWT marked as invalid in database",
		Category: "system",
	}
	ErrDbConnection = AuthError{
		Code:     10,
		Message:  "database connection error",
		Category: "system",
	}
	ErrDbInsertToken = AuthError{
		Code:     11,
		Message:  "failed to insert token",
		Category: "system",
	}
	ErrDbSelectUserFromToken = AuthError{
		Code:     12,
		Message:  "failed to select user from token",
		Category: "system",
	}
	ErrJwtGoodAccBadRef = AuthError{
		Code:     13,
		Message:  "access token was good but refresh was bad",
		Category: "system",
	}
	ErrDbInsertUsersToken = AuthError{
		Code:     14,
		Message:  "failed to insert users tokens",
		Category: "system",
	}
	ErrDbSelectUserFromJwt = AuthError{
		Code:     15,
		Message:  "failed to select user from JWT",
		Category: "system",
	}
	ErrDbUpdateTokensInvalid = AuthError{
		Code:     16,
		Message:  "failed to update tokens invalid",
		Category: "system",
	}
	ErrDbSelectUserSubject = AuthError{
		Code:     17,
		Message:  "failed to select user's subject by username",
		Category: "system",
	}
	ErrUuidFailed = func(msg string) AuthError {
		return AuthError{
			Code:     18,
			Message:  "failed to update tokens invalid",
			Category: "system",
		}
	}
)

func GetErrorByCategory(a []AuthError, category string) []AuthError {
	var filtered []AuthError
	for _, err := range a {
		if err.Category == category {
			filtered = append(filtered, err)
		}
	}
	return filtered
}

// IsUserError checks if an error is a user-facing error
func IsUserError(err error) bool {
	var ae AuthError
	if !errors.As(err, &ae) {
		return false
	}
	return ae.Category != "system"
}

// IsSystemError checks if an error is a system error
func IsSystemError(err error) bool {
	var ae AuthError
	if !errors.As(err, &ae) {
		return false
	}
	return ae.Category == "system"
}

func NewSystemError(err error) AuthError {
	return AuthError{
		Code:     99,
		Message:  "internal server error",
		Category: "system",
		Err:      err,
	}
}

// GetUserErrors returns all user errors from an error chain
func GetUserErrors(err error) []AuthError {
	var userErrs []AuthError
	for err != nil {
		var ae AuthError
		if errors.As(err, &ae) && ae.Category != "system" {
			userErrs = append(userErrs, ae)
		}
		err = errors.Unwrap(err)
	}
	return userErrs
}

var (
	ErrBadReqTodosBodyShort = errors.New("todos have a minimum length of 3 characters")
	Err404                  = errors.New("page not found")
	ErrProfileNotFound      = errors.New("profile not found")
	ErrUserSignedOut        = errors.New("you have been signed out")
)

var (
	ErrJwtInvalidType = errors.New("internal Server Error - 21013")
)

var (
	ErrDbInsertProfile     = errors.New("internal Server Error - 12402")
	ErrDbSelectTodosByUser = errors.New("internal Server Error - 12413")
)

var (
	ErrSessionNotFound = AuthError{
		Code:     10,
		Message:  "session not found",
		Category: "session",
	}
	ErrSessionExpired = AuthError{
		Code:     11,
		Message:  "session has expired",
		Category: "session",
	}
	ErrSessionInvalid = AuthError{
		Code:     12,
		Message:  "session is invalid",
		Category: "session",
	}
)
