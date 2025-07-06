package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/auth/providers/password"
	"github.com/nathan-hello/nat-auth/auth/providers/password/pwui"
	"github.com/nathan-hello/nat-auth/logger"
	"github.com/nathan-hello/nat-auth/storage"

	"github.com/nathan-hello/nat-auth/test/app/components"
)

func main() {
	store := storage.NewValkey("127.0.0.1:6379")
	password.InitJwt(password.AuthParams{
		PublicKeyPath:  "pub.pem",
		PrivateKeyPath: "key.pem",
		Secret:         "secret",
	})
	logger.LogLevel(slog.LevelDebug)
	logger.LogNewOutput(os.Stdout)

	p := password.PasswordHandler{
		Database: store,
		Ui: pwui.DefaultPasswordUi(pwui.DefaultPasswordUiParams{
			Theme: &pwui.Theme{
				Primary: pwui.ColorScheme{
					Light: "oklch(51.4% 0.222 16.935)",
					Dark:  "oklch(51.4% 0.222 16.935)",
				},
				Background: pwui.ColorScheme{
					Light: "oklch(29.3% 0.066 243.157)",
					Dark:  "oklch(29.3% 0.066 243.157)",
				},
				Logo: pwui.ColorScheme{
					Light: "/favicon.ico",
					Dark:  "/favicon.ico",
				},
				Title:   "NatAuth",
				Favicon: "/favicon.ico",
				Radius:  "none",
				Font: pwui.Font{
					Family: "Varela Round, sans-serif",
					Scale:  "1",
				},
			},
		}),
	}

	http.Handle("/", newRoute(HomeHandler))
	http.Handle("/auth/register", newRoute(p.SignUpHandler))
	http.Handle("/auth/login", newRoute(p.SignInHandler))
	http.Handle("/auth/logout", newRoute(p.SignOutHandler))
	http.Handle("/auth/logout/everywhere", newRoute(p.SignOutEverywhereHandler))
	http.Handle("/auth/forgot", newRoute(p.ForgotHandler))
	http.Handle("/auth/change", newRoute(p.ChangePassHandler))
	http.Handle("/auth/totp", newRoute(p.TotpHandler))
	http.Handle("/protected", newRoute(ProtectedHandler))

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Printf("Received shutdown signal, closing connections...")
		store.Client.Close()
		fmt.Printf("Valkey client closed")
		os.Exit(0)
	}()

	fmt.Println("Server starting on :3000")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		fmt.Printf("Server failed: %v", err)
	}
}

func newRoute(f http.HandlerFunc) http.Handler {
	return password.MiddlewareVerifyJwtAndInjectUserId(loggerMiddleware(http.HandlerFunc(f)))
}

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	userId := auth.GetUserId(r)
	if userId.Subject == "" || userId.Username == "" {
		logger.Log("app").Error("User ID not found in request context: %#v", userId)
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}
	components.Protected(userId.Subject).Render(r.Context(), w)
}

// HomeHandler handles the home route
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	userId := auth.GetUserId(r)
	w.Header().Set("Content-Type", "text/html")
	components.Root(userId.Subject).Render(r.Context(), w)
}

func loggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("request: %s %s\n", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
