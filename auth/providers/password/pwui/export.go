package pwui

import (
	"bytes"
	"net/http"

	"github.com/nathan-hello/nat-auth/auth/providers/password"
)

type DefaultPasswordUiParams struct {
	Theme     *Theme
	Copy      *PasswordUICopy
	ErrorCopy *PasswordUIErrorCopy
}

func DefaultPasswordUi(params DefaultPasswordUiParams) password.PasswordUi {

	var copy PasswordUICopy
	var errCopy PasswordUIErrorCopy
	var theme Theme
	if params.Theme == nil {
		theme = DefaultPasswordUITheme()
	}
	if params.Copy == nil {
		copy = DefaultPasswordUICopy()
	}
	if params.ErrorCopy == nil {
		errCopy = DefaultPasswordUIErrorCopy()
	}

	return password.PasswordUi{
		HtmlPageSignUp: func(r *http.Request) []byte {
			var buf bytes.Buffer
			PasswordUIRegister(theme, copy, errCopy, password.FormState{Type: "start"}, 0).Render(r.Context(), &buf)
			return buf.Bytes()
		},
		HtmlFormSignUp: func(r *http.Request, state password.FormState) []byte {
			var buf bytes.Buffer
			PasswordUIRegisterForm(copy, errCopy, state, 0).Render(r.Context(), &buf)
			return buf.Bytes()
		},
		HtmlPageSignIn: func(r *http.Request) []byte {
			var buf bytes.Buffer
			PasswordUILogin(theme, copy, errCopy, password.FormState{Type: "start"}, 0).Render(r.Context(), &buf)
			return buf.Bytes()
		},
		HtmlFormSignIn: func(r *http.Request, state password.FormState) []byte {
			var buf bytes.Buffer
			PasswordUILoginForm(copy, errCopy, state, 0).Render(r.Context(), &buf)
			return buf.Bytes()
		},
		HtmlPageChange: func(r *http.Request) []byte {
			var buf bytes.Buffer
			PasswordUIChange(theme, copy, errCopy, password.FormState{Type: "start"}, 0).Render(r.Context(), &buf)
			return buf.Bytes()
		},
		HtmlFormChange: func(r *http.Request, state password.FormState) []byte {
			var buf bytes.Buffer
			PasswordUIChangeStartForm(copy, state).Render(r.Context(), &buf)
			return buf.Bytes()
		},
	}
}
