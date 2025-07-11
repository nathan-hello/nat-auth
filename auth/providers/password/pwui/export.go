package pwui

import (
	"bytes"
	"net/http"
	"reflect"

	"github.com/nathan-hello/nat-auth/auth/providers/password"
	"github.com/nathan-hello/nat-auth/logger"
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
	Error               map[password.BitError]string
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
		Error: map[password.BitError]string{
			password.ErrPasswordTooLong:       "Password is too long.",
			password.ErrPasswordTooShort:      "Password is too short.",
			password.ErrUsernameInvalidFormat: "Username is not valid.",
			password.ErrUsernameTaken:         "Username is already taken.",
			password.ErrUsernameTooLong:       "Username is too long.",
			password.ErrUsernameTooShort:      "Username is too short.",
			password.ErrBadLogin:              "Invalid login credentials.",
			password.ErrPassNoMatch:           "Passwords do not match.",
			password.ErrInternalServer:        "Internal server error.",
			password.ErrTOTPMismatch:          "TOTP does not match.",
		},
	}
}

func IsZero[T any](x T) bool {
	// *new(T) is the zero value of T
	return reflect.DeepEqual(x, *new(T))
}

type DefaultPasswordUiParams struct {
	Theme Theme
	Copy  PasswordUICopy
}

func DefaultPasswordUi(params DefaultPasswordUiParams) password.PasswordUi {

	var copy PasswordUICopy
	var theme Theme
	if IsZero(params.Theme) {
		theme = DefaultPasswordUITheme()
	} else {
		theme = params.Theme
	}
	if IsZero(params.Copy) {
		copy = DefaultPasswordUICopy()
	} else {
		copy = params.Copy
	}

	logger.Log("DefaultPasswordUi").Info("theme: %#v", theme)
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
	}
}
