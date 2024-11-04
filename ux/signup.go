package ux

import (
	"context"
	"database/sql"
	"log"
	"time"

	"net/mail"

	"github.com/google/uuid"
	"github.com/nathan-hello/nat-auth/lib"
	"golang.org/x/crypto/bcrypt"
)

type PSignUp struct {
	Email      string
	Username   string
	Password   string
	PassConf   string
	AuthConfig lib.Config
	Db         DbAccessor
}

func validateStrings(a PSignUp) AuthResult {
	r := AuthResult{
		Errs: []AuthError{},
	}
	_, emailErr := mail.ParseAddress(a.Email)
	if emailErr != nil {
		if a.AuthConfig.EmailRequired {
			r.Errs = append(r.Errs, AuthError{Location: "email", Say: SayEmailInvalid})
		}
	}
	if len(a.Username) < 3 {
		if a.AuthConfig.UsernameRequired {
			r.Errs = append(r.Errs, AuthError{Location: "username", Say: SayUsernameShort})

		}
	}

	if a.Username == "" && a.Email == "" {
		r.Errs = append(r.Errs, AuthError{Location: "username_email", Say: SayEnterUserOrEmail})
	}

	if !a.AuthConfig.PasswordValidate(a.Password) {
		r.Errs = append(r.Errs, AuthError{Location: "password", Say: SayPasswordInvalid})
	}
	if a.Password != a.PassConf {
		r.Errs = append(r.Errs, AuthError{Location: "password", Say: SayPasswordNoMatch})
	}
	return r
}

// The caller is required to do the Insert to their database.
func SignUp(a PSignUp) AuthResult {
	ok := validateStrings(a)
	if ok.Errs != nil && len(ok.Errs) > 0 {
		return ok
	}

	errs := []AuthError{}

	ctx := context.Background()

	if a.Email != "" {
		_, err := a.Db.SelectUserByEmail(ctx, a.Email)
		if err != sql.ErrNoRows {
			errs = append(errs, AuthError{Location: "email", Say: SayEmailTaken})
		}
	}
	if a.Username != "" {
		_, err := a.Db.SelectUserByUsername(ctx, a.Username)
		if err != sql.ErrNoRows {
			errs = append(errs, AuthError{Location: "username", Say: SayUsernameTaken})
		}
	}
	if len(errs) > 0 {
		return AuthResult{Errs: errs}
	}

	userId := uuid.NewString()
	salt := uuid.NewString()[:8]
	pass, err := bcrypt.GenerateFromPassword([]byte(a.Password+salt), bcrypt.DefaultCost)

	if err != nil {
		log.Println(err)
		errs = append(errs, AuthError{Location: "misc", Say: SayHashPassword})
		return AuthResult{Errs: errs}
	}

	newUser := User{
		ID:                userId,
		Email:             a.Email,
		Username:          a.Username,
		EncryptedPassword: string(pass),
		PasswordSalt:      salt,
		PasswordCreatedAt: time.Now(),
	}
	return AuthResult{Errs: nil, User: newUser}
}
