package main

import (
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/auth/providers/password"
	"github.com/nathan-hello/nat-auth/httpwr"
	"github.com/nathan-hello/nat-auth/storage/valkey"
	"github.com/nathan-hello/nat-auth/test/app/components"
	"github.com/nathan-hello/nat-auth/utils"
)

func main() {
	store := valkey.VK{}
	store.InitDb("127.0.0.1:6379")
	utils.InitJwt(utils.ConfigJwt{
		Secret:        "secret",
		SecureCookie:  true,
		AccessExpiry:  1 * time.Hour,
		RefreshExpiry: 24 * time.Hour,
	}, "pub.pem", "key.pem")

	p := password.PasswordHandler{
		UsernameValidate: nil,
		Database:         &store,
		Redirects: password.PasswordRedirects{
			AfterSignIn: func(r *http.Request) string {
				return "/"
			},
			AfterSignUp: func(r *http.Request) string {
				return "/"
			},
			AfterSignOut: func(r *http.Request) string {
				return "/"
			},
		},
		Ui: password.PasswordUiDefault,
	}

	http.Handle("/", newRoute(HomeHandler))
	http.Handle("/auth/signup", newRoute(p.SignUpHandler))
	http.Handle("/auth/signin", newRoute(p.SignInHandler))
	http.Handle("/protected", newRoute(ProtectedHandler))

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		utils.Log("main").Info("Received shutdown signal, closing connections...")
		store.Client.Close()
		utils.Log("main").Info("Valkey client closed")
		os.Exit(0)
	}()

	utils.Log("main").Info("Server starting on :3000")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		utils.Log("main").Error("Server failed: %v", err)
	}
}

func newRoute(f http.HandlerFunc) http.Handler {
	return httpwr.VerifyJwtAndInjectUserId(httpwr.Logger(http.HandlerFunc(f)))
}

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	userId := auth.GetUserId(r)
	if userId == "" {
		utils.Log("protected-handler").Error("User ID not found in request context")
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}
	components.Protected(userId).Render(r.Context(), w)
}

// HomeHandler handles the home route
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	userId := auth.GetUserId(r)
	w.Header().Set("Content-Type", "text/html")
	components.Root(userId).Render(r.Context(), w)
}
