package ui

import (
	"bytes"
	_ "embed"
	"net/http"

	"github.com/nathan-hello/nat-auth/providers/password"
	"github.com/nathan-hello/nat-auth/providers/totp"
	"github.com/nathan-hello/nat-auth/web"
)

type PasswordUICopy struct {
	ButtonContinue      string
	CodeResend          string
	CodeReturn          string
	ForgotPrompt        string
	InputCode           string
	InputPassword       string
	InputRepeat         string
	InputUsername       string
	Login               string
	LoginDescription    string
	LoginPrompt         string
	LoginTitle          string
	Register            string
	RegisterDescription string
	RegisterPrompt      string
	RegisterTitle       string
	TotpInfo            string
	TotpPlaceholder     string
	TotpReroll          string
	TotpSkip            string
	TotpTest            string
	UsernamePlaceholder string
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
		InputUsername:       "Username",
		InputPassword:       "Password",
		InputCode:           "Code",
		InputRepeat:         "Repeat password",
		ButtonContinue:      "Continue",
		UsernamePlaceholder: "Username",
		TotpInfo:            "Use your TOTP to auth.",
		TotpPlaceholder:     "Code",
		Error: map[error]string{
			web.ErrPasswordTooLong:       "Password is too long.",
			web.ErrPasswordTooShort:      "Password is too short.",
			web.ErrUsernameInvalidFormat: "Username is not valid.",
			web.ErrUsernameTaken:         "Username is already taken.",
			web.ErrUsernameTooLong:       "Username is too long.",
			web.ErrUsernameTooShort:      "Username is too short.",
			web.ErrBadLogin:              "Invalid login credentials.",
			web.ErrPassNoMatch:           "Passwords do not match.",
			web.ErrTOTPMismatch:          "TOTP does not match.",
			web.ErrInternalServer:        "An error occurred. Please try again.",
			web.ErrTotpNotFound:          "Internal Server Error",
		},
	}
}

//go:embed styles.css
var styles []byte

var locations web.Locations

type UiParams struct {
	password.PasswordUi
	totp.TotpUi
	Styles []byte
}

func New(theme Theme, copy PasswordUICopy, l web.Locations) UiParams {
	locations = l

	return UiParams{
		PasswordUi: password.PasswordUi{
			HtmlPageSignUp: func(r *http.Request, state password.AuthFormState) []byte {
				var buf bytes.Buffer
				Register(theme, copy, state).Render(r.Context(), &buf)
				return buf.Bytes()
			},
			HtmlPageSignIn: func(r *http.Request, state password.AuthFormState) []byte {
				var buf bytes.Buffer
				Login(theme, copy, state).Render(r.Context(), &buf)
				return buf.Bytes()
			},
			HtmlPageChange: func(r *http.Request, state password.AuthFormState) []byte {
				var buf bytes.Buffer
				Change(theme, copy, state).Render(r.Context(), &buf)
				return buf.Bytes()
			},
			HtmlPageForgot: func(r *http.Request, state password.AuthFormState) []byte {
				var buf bytes.Buffer
				Forgot(theme, copy, state).Render(r.Context(), &buf)
				return buf.Bytes()
			},
		},
		TotpUi: totp.TotpUi{
			HtmlPageTotp: func(r *http.Request, state totp.TotpFormState, qr []byte, skipRedirectUrl string, totpSecret string) []byte {
				var buf bytes.Buffer
				TOTPSetup(theme, copy, state, qr, skipRedirectUrl, totpSecret)
				return buf.Bytes()
			},
		},
		Styles: styles,
	}
}
