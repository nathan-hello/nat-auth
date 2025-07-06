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
	HtmlPageSignUp func(*http.Request) []byte
	HtmlFormSignUp func(*http.Request, FormState) []byte
	HtmlPageSignIn func(*http.Request) []byte
	HtmlFormSignIn func(*http.Request, FormState) []byte
	HtmlPageChange func(*http.Request) []byte
	HtmlFormChange func(*http.Request, FormState) []byte
}

type RedirectFunc func(*http.Request) string

type PasswordRedirects struct {
	BeforeSignUp  RedirectFunc
	BeforeSignIn  RedirectFunc
	BeforeSignOut RedirectFunc
	BeforeChange  RedirectFunc
	AfterSignUp   RedirectFunc
	AfterSignIn   RedirectFunc
	AfterSignOut  RedirectFunc
	AfterChange   RedirectFunc
}

type PasswordHandler struct {
	UsernameValidate func(s string) BitError
	Database         storage.DbPassword
	Ui               PasswordUi
	Redirects        PasswordRedirects
}
