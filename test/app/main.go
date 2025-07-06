package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/a-h/templ"
	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/auth/providers/password"
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

	templ.Raw()

	p := password.PasswordHandler{
		Database: store,
	}

	http.Handle("/", newRoute(HomeHandler))
	http.Handle("/auth/signup", newRoute(p.SignUpHandler))
	http.Handle("/auth/signin", newRoute(p.SignInHandler))
	http.Handle("/auth/signout", newRoute(p.SignOutHandler))
	http.Handle("/auth/signoutall", newRoute(p.SignOutEverywhereHandler))
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
	return password.MiddlewareVerifyJwtAndInjectUserId(logger(http.HandlerFunc(f)))
}

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	userId := auth.GetUserId(r)
	if userId == "" {
		fmt.Println("User ID not found in request context")
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

func logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("request: %s %s\n", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
