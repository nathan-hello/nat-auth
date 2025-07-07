package auth

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/nathan-hello/nat-auth/auth/providers/password"
	"github.com/nathan-hello/nat-auth/auth/providers/password/pwui"
	"github.com/nathan-hello/nat-auth/logger"
	"github.com/nathan-hello/nat-auth/storage"
)

func NewNatAuth(middleware func(next http.Handler) http.Handler, privateKeyPath, publicKeyPath, secret string) (middlewares func(next http.HandlerFunc) http.Handler, onClose func()) {

	middlewares = func(next http.HandlerFunc) http.Handler {
		return password.MiddlewareVerifyJwtAndInjectUserId(middleware(next))
	}

	store := storage.NewValkey("127.0.0.1:6379")
	password.InitJwt(password.AuthParams{
		PublicKeyPath:  publicKeyPath,
		PrivateKeyPath: privateKeyPath,
		Secret:         secret,
	})
	logger.LogLevel(slog.LevelDebug)
	logger.LogNewOutput(os.Stdout)

	p := password.PasswordHandler{
		Database: store,
		Ui: pwui.DefaultPasswordUi(pwui.DefaultPasswordUiParams{
			Theme: pwui.Theme{
				Primary: pwui.ColorScheme{
					Light: "#262626",
					Dark:  "#262626",
				},
				Background: pwui.ColorScheme{
					Light: "#171717",
					Dark:  "#171717",
				},
				Logo: pwui.ColorScheme{
					Light: "https://reluekiss.com/favicon.svg",
					Dark:  "https://reluekiss.com/favicon.svg",
				},
				Title:   "Nat/e",
				Favicon: "https://reluekiss.com/favicon.svg",
				Radius:  "none",
				Font: pwui.Font{
					Family: "Varela Round, sans-serif",
					Scale:  "1",
				},
			},
			Copy: pwui.DefaultPasswordUICopy(),
		}),
	}
	http.Handle("/auth/register", middlewares(p.SignUpHandler))
	http.Handle("/auth/login", middlewares(p.SignInHandler))
	http.Handle("/auth/logout", middlewares(p.SignOutHandler))
	http.Handle("/auth/logout/everywhere", middlewares(p.SignOutEverywhereHandler))
	http.Handle("/auth/forgot", middlewares(p.ForgotHandler))
	http.Handle("/auth/change", middlewares(p.ChangePassHandler))
	http.Handle("/auth/totp", middlewares(p.TotpHandler))

	onClose = func() {
		store.Client.Close()
	}

	return middlewares, onClose
}
