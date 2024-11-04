package ux

import (
	"context"
	"net/mail"

	"golang.org/x/crypto/bcrypt"
)

type PSignIn struct {
	UserOrEmail string
	Password    string
	Db          DbAccessor
}

func SignIn(a PSignIn) AuthResult {
	r := AuthResult{Errs: []AuthError{}}
	if a.UserOrEmail == "" || a.Password == "" {
		r.Errs = append(r.Errs, AuthError{Location: "misc", Say: SayBadLogin})
		return r
	}

	ctx := context.Background()

	fetchUser := func() (user interface{}, err error) {
		if _, err := mail.ParseAddress(a.UserOrEmail); err == nil {
			return a.Db.SelectUserByEmailWithPassword(ctx, a.UserOrEmail)
		}
		return a.Db.SelectUserByUsernameWithPassword(ctx, a.UserOrEmail)
	}

	user, err := fetchUser()
	if err != nil {
		r.Errs = append(r.Errs, AuthError{Location: "username_email", Say: SayBadLogin, Err: err})
		return r
	}

	parsedUser, err := GetUserFields(user)
	if err != nil {
		r.Errs = append(r.Errs, AuthError{Location: "misc", Say: SayBadLogin, Err: err})
		return r
	}

	err = bcrypt.CompareHashAndPassword([]byte(parsedUser.EncryptedPassword), []byte(a.Password+parsedUser.PasswordSalt))
	if err != nil {
		r.Errs = append(r.Errs, AuthError{Location: "misc", Say: SayBadLogin})
		return r
	}

	r.Errs = nil
	r.User = User{
		ID:       parsedUser.ID,
		Email:    parsedUser.Email,
		Username: parsedUser.Username,
	}

	return r

}
