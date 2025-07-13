package ui

import (
	"bytes"
	_ "embed"
	"net/http"

	"github.com/nathan-hello/nat-auth/providers/password"
	"github.com/nathan-hello/nat-auth/web"
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
	ForgotPrompt        string
	CodeResend          string
	CodeReturn          string
	InputEmail          string
	InputPassword       string
	InputCode           string
	InputRepeat         string
	ButtonContinue      string
	TotpTest            string
	TotpSkip            string
	EmailPlaceholder    string
	TotpInfo            string
	TotpPlaceholder     string
	Error               map[error]string
}

func DefaultPasswordUITheme() Theme {
	return Theme{
		Title: "NatAuth",
		Logo: ColorScheme{
			Light: "/favicon.ico",
			Dark:  "/favicon.ico",
		},
		Background: ColorScheme{
			Light: "white",
			Dark:  "white",
		},
		Primary: ColorScheme{
			Light: "blue",
			Dark:  "blue",
		},
		Font: Font{
			Family: "Varela Round, sans-serif",
			Scale:  "1",
		},
	}
}

func DefaultPasswordUICopy() PasswordUICopy {
	return PasswordUICopy{
		RegisterTitle:       "Welcome to the app",
		RegisterDescription: "Sign in with your email",
		TotpTest:            "Test!",
		TotpSkip:            "Skip",
		LoginTitle:          "Welcome to the app",
		LoginDescription:    "Sign in with your email",
		Register:            "Register",
		RegisterPrompt:      "Don't have an account?",
		LoginPrompt:         "Already have an account?",
		Login:               "Login",
		ForgotPrompt:        "Forgot password?",
		CodeResend:          "Resend code",
		CodeReturn:          "Back to",
		InputEmail:          "Email",
		InputPassword:       "Password",
		InputCode:           "Code",
		InputRepeat:         "Repeat password",
		ButtonContinue:      "Continue",
		EmailPlaceholder:    "Email",
		TotpInfo:            "Use your TOTP to auth.",
		TotpPlaceholder:     "Code",
		Error: map[error]string{
			password.ErrPasswordTooLong:       "Password is too long.",
			password.ErrPasswordTooShort:      "Password is too short.",
			password.ErrUsernameInvalidFormat: "Username is not valid.",
			password.ErrUsernameTaken:         "Username is already taken.",
			password.ErrUsernameTooLong:       "Username is too long.",
			password.ErrUsernameTooShort:      "Username is too short.",
			password.ErrBadLogin:              "Invalid login credentials.",
			password.ErrPassNoMatch:           "Passwords do not match.",
			password.ErrTOTPMismatch:          "TOTP does not match.",
			password.ErrInternalServer:        "An error occurred. Please try again.",
		},
	}
}

//go:embed styles.css
var styles []byte

var locations web.Locations

func New(theme Theme, copy PasswordUICopy, l web.Locations) (password.PasswordUi, []byte) {
	locations = l

	return password.PasswordUi{
		HtmlPageSignUp: func(r *http.Request, state password.FormState) []byte {
			var buf bytes.Buffer
			Register(theme, copy, state).Render(r.Context(), &buf)
			return buf.Bytes()
		},
		HtmlPageSignIn: func(r *http.Request, state password.FormState) []byte {
			var buf bytes.Buffer
			Login(theme, copy, state).Render(r.Context(), &buf)
			return buf.Bytes()
		},
		HtmlPageChange: func(r *http.Request, state password.FormState) []byte {
			var buf bytes.Buffer
			Change(theme, copy, state).Render(r.Context(), &buf)
			return buf.Bytes()
		},
		HtmlPageForgot: func(r *http.Request, state password.FormState) []byte {
			var buf bytes.Buffer
			Forgot(theme, copy, state).Render(r.Context(), &buf)
			return buf.Bytes()
		},
		HtmlPageTotp: func(r *http.Request, state password.FormState, qr []byte, skipRedirectUrl string, totpSecret string) []byte {
			var buf bytes.Buffer
			TOTPSetup(theme, copy, state, qr, skipRedirectUrl, totpSecret).Render(r.Context(), &buf)
			return buf.Bytes()
		},
	}, styles
}
