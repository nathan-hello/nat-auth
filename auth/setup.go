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

func NewNatAuth(middleware func(next http.Handler) http.Handler, privateKeyPath, publicKeyPath, secret string) func() {

	route := func(f http.HandlerFunc) http.Handler {
		return password.MiddlewareVerifyJwtAndInjectUserId(middleware(http.HandlerFunc(f)))
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
					Light: "oklch(51.4% 0.222 16.935)",
					Dark:  "oklch(51.4% 0.222 16.935)",
				},
				Background: pwui.ColorScheme{
					Light: "oklch(29.3% 0.066 243.157)",
					Dark:  "oklch(29.3% 0.066 243.157)",
				},
				Logo: pwui.ColorScheme{
					Light: "https://reluekiss.com/favicon.svg",
					Dark:  "https://reluekiss.com/favicon.svg",
				},
				Title:   "NatAuth",
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
	http.Handle("/auth/register", route(p.SignUpHandler))
	http.Handle("/auth/login", route(p.SignInHandler))
	http.Handle("/auth/logout", route(p.SignOutHandler))
	http.Handle("/auth/logout/everywhere", route(p.SignOutEverywhereHandler))
	http.Handle("/auth/forgot", route(p.ForgotHandler))
	http.Handle("/auth/change", route(p.ChangePassHandler))
	http.Handle("/auth/totp", route(p.TotpHandler))

	onClose := func() {
		store.Client.Close()
	}
	return onClose
}
