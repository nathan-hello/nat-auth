package err

import (
	"errors"
	"fmt"
)

type AuthError struct {
	Code     string
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
		Code:     "AUTH_001",
		Message:  "username must be at least 3 characters long",
		Category: "username",
	}
	ErrUsernameTooLong = AuthError{
		Code:     "AUTH_002",
		Message:  "username must be at most 30 characters long",
		Category: "username",
	}
	ErrUsernameInvalidFormat = AuthError{
		Code:     "AUTH_003",
		Message:  "username can only contain letters, numbers, underscores, and hyphens",
		Category: "username",
	}
	ErrEmailInvalid = AuthError{
		Code:     "AUTH_004",
		Message:  "invalid email format",
		Category: "email",
	}
	ErrEmailOrUsernameReq = AuthError{
		Code:     "AUTH_005",
		Message:  "email or username is required",
		Category: "username",
	}
	ErrEmailTaken = AuthError{
		Code:     "AUTH_006",
		Message:  "email is already taken",
		Category: "email",
	}
	ErrUsernameTaken = AuthError{
		Code:     "AUTH_007",
		Message:  "username is already taken",
		Category: "username",
	}
	ErrPasswordInvalid = AuthError{
		Code:     "AUTH_008",
		Message:  "password must be at least 8 characters long",
		Category: "password",
	}
	ErrPassNoMatch = AuthError{
		Code:     "AUTH_009",
		Message:  "passwords do not match",
		Category: "password",
	}
	ErrBadLogin = AuthError{
		Code:     "AUTH_010",
		Message:  "invalid username/email or password",
		Category: "login",
	}
)

// System errors that should not be exposed to users
var (
	ErrHashPassword = AuthError{
		Code:     "SYS_001",
		Message:  "failed to hash password",
		Category: "system",
	}
	ErrDbInsertUser = AuthError{
		Code:     "SYS_002",
		Message:  "failed to insert user",
		Category: "system",
	}
	ErrDbSelectAfterInsert = AuthError{
		Code:     "SYS_003",
		Message:  "failed to retrieve user after insert",
		Category: "system",
	}
	ErrParsingJwt = AuthError{
		Code:     "SYS_004",
		Message:  "failed to parse JWT",
		Category: "system",
	}
	ErrInvalidToken = AuthError{
		Code:     "SYS_005",
		Message:  "invalid token",
		Category: "system",
	}
	ErrJwtNotInHeader = AuthError{
		Code:     "SYS_006",
		Message:  "JWT not found in header",
		Category: "system",
	}
	ErrJwtNotInDb = AuthError{
		Code:     "SYS_007",
		Message:  "JWT not found in database",
		Category: "system",
	}
	ErrJwtMethodBad = AuthError{
		Code:     "SYS_008",
		Message:  "invalid JWT signing method",
		Category: "system",
	}
	ErrJwtInvalidInDb = AuthError{
		Code:     "SYS_009",
		Message:  "JWT marked as invalid in database",
		Category: "system",
	}
	ErrDbConnection = AuthError{
		Code:     "SYS_010",
		Message:  "database connection error",
		Category: "system",
	}
	ErrDbInsertToken = AuthError{
		Code:     "SYS_011",
		Message:  "failed to insert token",
		Category: "system",
	}
	ErrDbSelectUserFromToken = AuthError{
		Code:     "SYS_012",
		Message:  "failed to select user from token",
		Category: "system",
	}
	ErrJwtGoodAccBadRef = AuthError{
		Code:     "SYS_013",
		Message:  "access token was good but refresh was bad",
		Category: "system",
	}
	ErrDbInsertUsersToken = AuthError{
		Code:     "SYS_014",
		Message:  "failed to insert users tokens",
		Category: "system",
	}
	ErrDbSelectUserFromJwt = AuthError{
		Code:     "SYS_015",
		Message:  "failed to select user from JWT",
		Category: "system",
	}
	ErrDbUpdateTokensInvalid = AuthError{
		Code:     "SYS_016",
		Message:  "failed to update tokens invalid",
		Category: "system",
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
		Code:     "SYS_017",
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
		Code:     "AUTH_010",
		Message:  "session not found",
		Category: "session",
	}
	ErrSessionExpired = AuthError{
		Code:     "AUTH_011",
		Message:  "session has expired",
		Category: "session",
	}
	ErrSessionInvalid = AuthError{
		Code:     "AUTH_012",
		Message:  "session is invalid",
		Category: "session",
	}
)
