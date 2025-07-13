package web

import "errors"

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
