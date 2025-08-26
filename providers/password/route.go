package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/storage"
)

type PasswordHandler struct {
	UsernameValidate func(s string) []error
	Database         storage.DbPassword
	Ui               PasswordUi
	Redirects        PasswordRedirects
}

type AuthFormState struct {
	Username string
	Errors   []error
}

type PasswordUi struct {
	HtmlPageSignUp func(*http.Request, AuthFormState) []byte
	HtmlPageSignIn func(*http.Request, AuthFormState) []byte
	HtmlPageChange func(*http.Request, AuthFormState) []byte
	HtmlPageForgot func(*http.Request, AuthFormState) []byte
}

type RedirectFunc func(*http.Request) string

type PasswordRedirects struct {
	BeforeSignUp  RedirectFunc
	BeforeSignIn  RedirectFunc
	BeforeSignOut RedirectFunc
	AfterSignUp   RedirectFunc
	AfterSignIn   RedirectFunc
	AfterSignOut  RedirectFunc
}
