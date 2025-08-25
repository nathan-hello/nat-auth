package natauth

import (
	"errors"
	"io"
	"net/http"

	"github.com/justinas/alice"
	"github.com/nathan-hello/nat-auth/providers/password"
	"github.com/nathan-hello/nat-auth/storage"
	"github.com/nathan-hello/nat-auth/ui"
	"github.com/nathan-hello/nat-auth/utils"
	"github.com/nathan-hello/nat-auth/web"
)

type Params struct {
	MiddlewaresBeforeAuth []alice.Constructor
	MiddlewaresAfterAuth  []alice.Constructor
	JwtConfig             web.PasswordJwtParams
	UsernameValidator     func(string) []error
	Redirects             password.PasswordRedirects
	Storage               storage.DbPassword
	Theme                 ui.Theme
	Locations             *web.Locations
	LogWriters            []io.Writer
	TotpIssuer            string
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

	if params.JwtConfig.Secret == "" {
		return Handlers{}, errors.New("password provider requires a secret")
	}

	err := web.InitJwt(params.JwtConfig)
	if err != nil {
		return Handlers{}, err
	}

	if params.Locations == nil {
		params.Locations = &defaultLocations
	}

	pwui, styles := ui.New(
		params.Theme,
		ui.DefaultPasswordUICopy(),
		*params.Locations,
	)
	p := password.PasswordHandler{
		UsernameValidate: params.UsernameValidator,
		Database:         params.Storage,
		Ui:               pwui,
		Redirects:        params.Redirects,
		TotpIssuer:       params.TotpIssuer,
	}

	route := func(s string, handler http.HandlerFunc) {
		var internal = []alice.Constructor{web.MiddlewareAuth, web.RejectSubroute(s)}
		chain := alice.New(append(append(params.MiddlewaresBeforeAuth, internal...), params.MiddlewaresAfterAuth...)...).ThenFunc(handler)
		http.Handle(s, chain)
	}

	route(params.Locations.SignIn, p.HandlerSignIn)
	route(params.Locations.SignUp, p.HandlerSignUp)
	route(params.Locations.Forgot, p.HandlerForgot)
	route(params.Locations.Change, p.HandlerChange)
	route(params.Locations.Totp, p.HandlerTotp)
	route(params.Locations.SignOut, p.HandlerSignOut)
	route(params.Locations.SignOutEverywhere, p.HandlerSignOutEverywhere)
	route(params.Locations.Styles, cssHandler(styles))

	var onClose = func() {
	}

	return Handlers{
		MiddlewareAuth: web.MiddlewareAuth,
		OnClose:        onClose,
	}, nil

}

func cssHandler(file []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Write(file)
	}
}
