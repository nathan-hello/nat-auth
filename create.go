package natauth

import (
	"errors"
	"io"
	"net/http"

	"github.com/justinas/alice"
	"github.com/nathan-hello/nat-auth/providers/password"
	"github.com/nathan-hello/nat-auth/providers/totp"
	"github.com/nathan-hello/nat-auth/storage"
	"github.com/nathan-hello/nat-auth/ui"
	"github.com/nathan-hello/nat-auth/utils"
	"github.com/nathan-hello/nat-auth/web"
)

type PasswordParams struct {
	UsernameValidator     func(string) []error
	JwtSecret             string
	JwePublicKeyPath      string
	JwePrivateKeyPath     string
	RedirectBeforeSignUp  password.RedirectFunc
	RedirectBeforeSignIn  password.RedirectFunc
	RedirectBeforeSignOut password.RedirectFunc
	RedirectAfterSignUp   password.RedirectFunc
	RedirectAfterSignIn   password.RedirectFunc
	RedirectAfterSignOut  password.RedirectFunc
}

type TotpParams struct {
	PrivateKeyPath string
	Issuer         string
}

type Params struct {
	MiddlewaresBeforeAuth []alice.Constructor
	MiddlewaresAfterAuth  []alice.Constructor
	Storage               storage.DbPassword
	Theme                 ui.Theme
	LogWriters            []io.Writer
	PasswordParams        PasswordParams
	TotpParams            TotpParams
}

var defaultLocations = web.Locations{
	SignIn:            "/auth/login",
	SignUp:            "/auth/register",
	Forgot:            "/auth/forgot",
	Change:            "/auth/change",
	Totp:              "/auth/totp",
	SignOut:           "/auth/signout",
	SignOutEverywhere: "/auth/signout-everywhere",
	Styles:            "/auth/styles.css",
}

type Handlers struct {
	MiddlewareAuth func(http.Handler) http.Handler
}

func New(params Params) (Handlers, error) {

	for _, w := range params.LogWriters {
		utils.LogNewOutput(w)
	}

	if params.PasswordParams.JwtSecret == "" {
		return Handlers{}, errors.New("password provider requires a secret")
	}

	err := web.InitJwt(web.PasswordJwtParams{
		Secret:         params.PasswordParams.JwtSecret,
		PublicKeyPath:  params.PasswordParams.JwePublicKeyPath,
		PrivateKeyPath: params.PasswordParams.JwePrivateKeyPath,
	})
	if err != nil {
		return Handlers{}, err
	}

	var styles []byte
	uiParams := ui.New(
		params.Theme,
		ui.DefaultPasswordUICopy(),
		defaultLocations,
	)

	route(defaultLocations.Styles, params.MiddlewaresBeforeAuth, params.MiddlewaresAfterAuth, cssHandler(styles))

	p := password.PasswordHandler{
		UsernameValidate: params.PasswordParams.UsernameValidator,
		Database:         params.Storage,
		Ui:               uiParams.PasswordUi,
		Redirects: password.PasswordRedirects{
			BeforeSignUp:  params.PasswordParams.RedirectAfterSignUp,
			BeforeSignIn:  params.PasswordParams.RedirectBeforeSignIn,
			BeforeSignOut: params.PasswordParams.RedirectBeforeSignOut,
			AfterSignUp:   params.PasswordParams.RedirectAfterSignUp,
			AfterSignIn:   params.PasswordParams.RedirectAfterSignIn,
			AfterSignOut:  params.PasswordParams.RedirectAfterSignOut,
		},
	}

	t := totp.TotpHandler{
		Issuer:   params.TotpParams.Issuer,
		Database: params.Storage,
		Ui:       uiParams.TotpUi,
	}

	route(defaultLocations.SignIn, params.MiddlewaresBeforeAuth, params.MiddlewaresAfterAuth, p.HandlerSignIn)
	route(defaultLocations.SignUp, params.MiddlewaresBeforeAuth, params.MiddlewaresAfterAuth, p.HandlerSignUp)
	route(defaultLocations.Forgot, params.MiddlewaresBeforeAuth, params.MiddlewaresAfterAuth, p.HandlerForgot)
	route(defaultLocations.Change, params.MiddlewaresBeforeAuth, params.MiddlewaresAfterAuth, p.HandlerChange)
	route(defaultLocations.Totp, params.MiddlewaresBeforeAuth, params.MiddlewaresAfterAuth, t.HandlerTotp)
	route(defaultLocations.SignOut, params.MiddlewaresBeforeAuth, params.MiddlewaresAfterAuth, p.HandlerSignOut)
	route(defaultLocations.SignOutEverywhere, params.MiddlewaresBeforeAuth, params.MiddlewaresAfterAuth, p.HandlerSignOutEverywhere)

	return Handlers{
		MiddlewareAuth: web.MiddlewareAuth,
	}, nil

}

func route(s string, beforeAuth []alice.Constructor, afterAuth []alice.Constructor, handler http.HandlerFunc) {
	var internal = []alice.Constructor{web.MiddlewareAuth, web.RejectSubroute(s)}
	chain := alice.New(append(append(beforeAuth, internal...), afterAuth...)...).ThenFunc(handler)
	http.Handle(s, chain)
}

func cssHandler(file []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Write(file)
	}
}
