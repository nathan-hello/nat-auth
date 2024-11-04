package ux

import (
	"context"
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

type DbAccessor interface {
	SelectUserById(ctx context.Context, id string) (interface{}, error)
	SelectUserByEmail(ctx context.Context, email string) (interface{}, error)
	SelectUserByEmailWithPassword(ctx context.Context, email string) (interface{}, error)
	SelectUserByUsername(ctx context.Context, username string) (interface{}, error)
	SelectUserByUsernameWithPassword(ctx context.Context, username string) (interface{}, error)
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
