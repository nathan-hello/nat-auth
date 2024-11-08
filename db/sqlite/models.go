// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0

package sqlite

import (
	"time"
)

type Token struct {
	ID      int64
	JwtType string
	Jwt     string
	Valid   bool
	Family  string
}

type User struct {
	ID                string
	Email             string
	Username          string
	PasswordSalt      string
	EncryptedPassword string
	PasswordCreatedAt time.Time
}

type UsersToken struct {
	UserID  string
	TokenID int64
}
