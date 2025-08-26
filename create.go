package natauth

import (
	"errors"
	"io"
	"net/http"
	"reflect"

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
	Locations             *web.Locations
	LogWriters            []io.Writer
	PasswordParams        PasswordParams
	TotpParams            TotpParams
	Ui                    Ui
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
	OnClose        func()
}

func New(params Params) (Handlers, error) {

	for _, w := range params.LogWriters {
		utils.LogNewOutput(w)
	}

	if params.Locations == nil {
		params.Locations = &defaultLocations
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

	if params.Locations == nil {
		params.Locations = &defaultLocations
	}

	asdfui := params.Ui

	uiVal := reflect.ValueOf(asdfui)
	uiZero := reflect.Zero(uiVal.Type())

	if reflect.DeepEqual(uiVal.Interface(), uiZero.Interface()) {
		var styles []byte
		asdfui, styles = ui.New(
			params.Theme,
			asdfui.DefaultPasswordUICopy(),
			*params.Locations,
		)
		route(params.Locations.Styles, params.MiddlewaresBeforeAuth, params.MiddlewaresAfterAuth, cssHandler(styles))
	}

	p := password.PasswordHandler{
		UsernameValidate: params.PasswordParams.UsernameValidator,
		Database:         params.Storage,
		Ui:               pwui,
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
		Ui:       pwui,
	}

	route(params.Locations.SignIn, params.MiddlewaresBeforeAuth, params.MiddlewaresAfterAuth, p.HandlerSignIn)
	route(params.Locations.SignUp, params.MiddlewaresBeforeAuth, params.MiddlewaresAfterAuth, p.HandlerSignUp)
	route(params.Locations.Forgot, params.MiddlewaresBeforeAuth, params.MiddlewaresAfterAuth, p.HandlerForgot)
	route(params.Locations.Change, params.MiddlewaresBeforeAuth, params.MiddlewaresAfterAuth, p.HandlerChange)
	route(params.Locations.Totp, params.MiddlewaresBeforeAuth, params.MiddlewaresAfterAuth, p.HandlerTotp)
	route(params.Locations.SignOut, params.MiddlewaresBeforeAuth, params.MiddlewaresAfterAuth, p.HandlerSignOut)
	route(params.Locations.SignOutEverywhere, params.MiddlewaresBeforeAuth, params.MiddlewaresAfterAuth, p.HandlerSignOutEverywhere)

	var onClose = func() {
	}

	return Handlers{
		MiddlewareAuth: web.MiddlewareAuth,
		OnClose:        onClose,
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
