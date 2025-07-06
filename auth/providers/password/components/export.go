package components

import (
	"bytes"
	"net/http"

	"github.com/nathan-hello/nat-auth/auth/providers/password"
)

var PasswordUiDefault = password.PasswordUi{
	HtmlPageSignUp: func(r *http.Request) []byte {
		var buf bytes.Buffer
		SignUp("", 0).Render(r.Context(), &buf)
		return buf.Bytes()
	},
	HtmlFormSignUp: func(r *http.Request, state password.FormState) []byte {
		var buf bytes.Buffer
		SignUpForm(state.Username, state.Errors).Render(r.Context(), &buf)
		return buf.Bytes()
	},
	HtmlPageSignIn: func(r *http.Request) []byte {
		var buf bytes.Buffer
		SignIn("", 0).Render(r.Context(), &buf)
		return buf.Bytes()
	},
	HtmlFormSignIn: func(r *http.Request, state password.FormState) []byte {
		var buf bytes.Buffer
		SignInForm(state.Username, state.Errors).Render(r.Context(), &buf)
		return buf.Bytes()
	},
	HtmlPageChange: func(r *http.Request) []byte {
		var buf bytes.Buffer
		ChangePass(0).Render(r.Context(), &buf)
		return buf.Bytes()
	},
	HtmlFormChange: func(r *http.Request, state password.FormState) []byte {
		var buf bytes.Buffer
		ChangePassForm(state.Errors).Render(r.Context(), &buf)
		return buf.Bytes()
	},
}
