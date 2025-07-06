package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/storage"
)

type FormState struct {
	Username string
	Errors   BitError
	Type     string // "start", "code", "update"
}

type PasswordUi struct {
	HtmlPageSignUp func(*http.Request, FormState) []byte
	HtmlPageSignIn func(*http.Request, FormState) []byte
	HtmlPageChange func(*http.Request, FormState) []byte
	HtmlPageTotp   func(*http.Request, FormState) []byte
}

type RedirectFunc func(*http.Request) string

type PasswordRedirects struct {
	BeforeSignUp  RedirectFunc
	BeforeSignIn  RedirectFunc
	BeforeSignOut RedirectFunc
	BeforeChange  RedirectFunc
	BeforeTotp    RedirectFunc
	AfterSignUp   RedirectFunc
	AfterSignIn   RedirectFunc
	AfterSignOut  RedirectFunc
	AfterChange   RedirectFunc
	AfterTotp     RedirectFunc
}

type PasswordHandler struct {
	UsernameValidate func(s string) BitError
	Database         storage.DbPassword
	Ui               PasswordUi
	Redirects        PasswordRedirects
}
