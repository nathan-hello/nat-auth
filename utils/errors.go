package utils

import (
	"context"
	"errors"
	"time"
)

type User struct {
	ID                string
	Email             string
	Username          string
	PasswordSalt      string
	EncryptedPassword string
	PasswordCreatedAt time.Time
}

type AuthError struct {
	Location string
	Say      string
	Err      error
}

type AuthResult struct {
	Errs []AuthError
	User User
}

type DbAccessor[T any] interface {
	SelectUserById(ctx context.Context, id string) (T, error)
	SelectUserByEmail(ctx context.Context, email string) (T, error)
	SelectUserByEmailWithPassword(ctx context.Context, email string) (T, error)
	SelectUserByUsername(ctx context.Context, username string) (T, error)
	SelectUserByUsernameWithPassword(ctx context.Context, username string) (T, error)
}

// User-facing messages
var (
	SayEmailInvalid     = "Email invalid."
	SayUsernameShort    = "Username is too short."
	SayEnterUserOrEmail = "Enter a username or email."
	SayPasswordInvalid  = "Password is invalid."
	SayPasswordNoMatch  = "Passwords do not match."
	SayEmailTaken       = "Email is taken."
	SayUsernameTaken    = "Username is taken."
	SayBadLogin         = "Incorrect password or account does not exist"
	SayParseForm        = "internal Server Error - 13481"
	SayAuthStateNil     = "internal Server Error - 13483"
	SayHashPassword     = "internal Server Error - 19283"
	SayDbInsertUser     = "internal Server Error - 12405"
	SayReflect          = "internal Server Error - 12405"
)

var (
	ErrParsingJwt       = errors.New("internal Server Error - 10001")
	ErrInvalidToken     = errors.New("internal Server Error - 10002")
	ErrJwtNotInHeader   = errors.New("internal Server Error - 10003")
	ErrJwtNotInDb       = errors.New("internal Server Error - 10004")
	ErrJwtMethodBad     = errors.New("internal Server Error - 10005")
	ErrJwtInvalidInDb   = errors.New("internal Server Error - 10006")
	ErrJwtInsertInDb    = errors.New("internal Server Error - 10007")
	ErrJwtGetSubject    = errors.New("internal Server Error - 10008")
	ErrJwtPairInvalid   = errors.New("internal Server Error - 10009")
	ErrJwtGoodAccBadRef = errors.New("internal Server Error - 10010")
)
