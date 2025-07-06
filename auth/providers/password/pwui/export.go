package pwui

import (
	"bytes"
	"net/http"

	"github.com/nathan-hello/nat-auth/auth/providers/password"
)

type PasswordUICopy struct {
	RegisterTitle       string
	RegisterDescription string
	LoginTitle          string
	LoginDescription    string
	Register            string
	RegisterPrompt      string
	LoginPrompt         string
	Login               string
	ChangePrompt        string
	CodeResend          string
	CodeReturn          string
	Logo                string
	InputEmail          string
	InputPassword       string
	InputCode           string
	InputRepeat         string
	ButtonContinue      string
}

type PasswordUIErrorCopy map[password.BitError]string

func DefaultPasswordUITheme() Theme {
	return Theme{
		Title:      "NatAuth",
		Logo:       "/favicon.ico",
		Background: "white",
		Primary:    "blue",
		Font: Font{
			Family: "Varela Round, sans-serif",
			Scale:  "1",
		},
	}
}

func DefaultPasswordUIErrorCopy() PasswordUIErrorCopy {
	return PasswordUIErrorCopy{
		password.ErrInvalidCode:           "Code is incorrect.",
		password.ErrInvalidEmail:          "Email is not valid.",
		password.ErrInvalidPassword:       "Password is incorrect.",
		password.ErrPasswordMismatch:      "Passwords do not match.",
		password.ErrPasswordTooLong:       "Password is too long.",
		password.ErrPasswordTooShort:      "Password is too short.",
		password.ErrUsernameInvalidFormat: "Username is not valid.",
		password.ErrUsernameTaken:         "Username is already taken.",
		password.ErrUsernameTooLong:       "Username is too long.",
		password.ErrUsernameTooShort:      "Username is too short.",
		password.ErrInternalServer:        "Internal server error.",
		password.ErrTOTPMismatch:          "TOTP does not match.",
	}
}

func DefaultPasswordUICopy() PasswordUICopy {
	return PasswordUICopy{
		RegisterTitle:       "Welcome to the app",
		RegisterDescription: "Sign in with your email",
		LoginTitle:          "Welcome to the app",
		LoginDescription:    "Sign in with your email",
		Register:            "Register",
		RegisterPrompt:      "Don't have an account?",
		LoginPrompt:         "Already have an account?",
		Login:               "Login",
		ChangePrompt:        "Forgot password?",
		CodeResend:          "Resend code",
		CodeReturn:          "Back to",
		Logo:                "A",
		InputEmail:          "Email",
		InputPassword:       "Password",
		InputCode:           "Code",
		InputRepeat:         "Repeat password",
		ButtonContinue:      "Continue",
	}
}

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
		HtmlPageSignUp: func(r *http.Request, state password.FormState) []byte {
			var buf bytes.Buffer
			Register(theme, copy, errCopy, state).Render(r.Context(), &buf)
			return buf.Bytes()
		},
		HtmlPageSignIn: func(r *http.Request, state password.FormState) []byte {
			var buf bytes.Buffer
			Login(theme, copy, errCopy, state).Render(r.Context(), &buf)
			return buf.Bytes()
		},
		HtmlPageChange: func(r *http.Request, state password.FormState) []byte {
			var buf bytes.Buffer
			Change(theme, copy, errCopy, state).Render(r.Context(), &buf)
			return buf.Bytes()
		},
	}
}
