package password

import (
	"bytes"
	"net/http"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/providers/password/components"
	"github.com/nathan-hello/nat-auth/storage"
)

type FormState struct {
	Username string
	Errors   auth.BitError
}

type PasswordUi struct {
	HtmlPageSignUp func(*http.Request) []byte
	HtmlFormSignUp func(*http.Request, FormState) []byte
	HtmlPageSignIn func(*http.Request) []byte
	HtmlFormSignIn func(*http.Request, FormState) []byte
}

var PasswordUiDefault = PasswordUi{
	HtmlPageSignUp: func(r *http.Request) []byte {
		var buf bytes.Buffer
		components.SignUp("", 0).Render(r.Context(), &buf)
		return buf.Bytes()
	},
	HtmlFormSignUp: func(r *http.Request, state FormState) []byte {
		var buf bytes.Buffer
		components.SignUpForm(state.Username, state.Errors).Render(r.Context(), &buf)
		return buf.Bytes()
	},
	HtmlPageSignIn: func(r *http.Request) []byte {
		var buf bytes.Buffer
		components.SignIn("", 0).Render(r.Context(), &buf)
		return buf.Bytes()
	},
	HtmlFormSignIn: func(r *http.Request, state FormState) []byte {
		var buf bytes.Buffer
		components.SignInForm(state.Username, state.Errors).Render(r.Context(), &buf)
		return buf.Bytes()
	},
}

type PasswordHandler struct {
	UsernameValidate    func(s string) auth.BitError
	Database            storage.DbPassword
	RedirectAfterSignUp func(*http.Request) string
	RedirectAfterSignIn func(*http.Request) string
	Ui                  PasswordUi
}
