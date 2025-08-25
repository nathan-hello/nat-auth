package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/storage"
)

type PasswordHandler struct {
	TotpIssuer       string
	UsernameValidate func(s string) []error
	Database         storage.DbPassword
	Ui               PasswordUi
	Redirects        PasswordRedirects
}

type FormState struct {
	Username string
	Errors   []error
}

type PasswordUi struct {
	HtmlPageSignUp func(*http.Request, FormState) []byte
	HtmlPageSignIn func(*http.Request, FormState) []byte
	HtmlPageChange func(*http.Request, FormState) []byte
	HtmlPageForgot func(*http.Request, FormState) []byte
	HtmlPageTotp   func(r *http.Request, state FormState, qr []byte, skipRedirectUrl string, totpSecret string) []byte
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
