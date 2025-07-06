package password

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/storage"
)

type FormState struct {
	Username string
	Errors   BitError
}

type PasswordUi struct {
	HtmlPageSignUp func(*http.Request) []byte
	HtmlFormSignUp func(*http.Request, FormState) []byte
	HtmlPageSignIn func(*http.Request) []byte
	HtmlFormSignIn func(*http.Request, FormState) []byte
	HtmlPageChange func(*http.Request) []byte
	HtmlFormChange func(*http.Request, FormState) []byte
}

type PasswordRedirects struct {
	BeforeSignUp  func(*http.Request) string
	BeforeSignIn  func(*http.Request) string
	BeforeSignOut func(*http.Request) string
	BeforeChange  func(*http.Request) string
	AfterSignUp   func(*http.Request) string
	AfterSignIn   func(*http.Request) string
	AfterSignOut  func(*http.Request) string
	AfterChange   func(*http.Request) string
}

type PasswordHandler struct {
	UsernameValidate func(s string) BitError
	Database         storage.DbPassword
	Ui               PasswordUi
	Redirects        PasswordRedirects
}
