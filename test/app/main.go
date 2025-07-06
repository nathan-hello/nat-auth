package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/auth/user"

	"github.com/nathan-hello/nat-auth/test/app/components"
)

func main() {
	middlewares, onClose := auth.NewNatAuth(loggerMiddleware, "pub.pem", "key.pem", "secret")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Printf("Received shutdown signal, closing connections...")
		onClose()
		fmt.Printf("Valkey client closed")
		os.Exit(0)
	}()

	http.Handle("/", middlewares(HomeHandler))
	http.Handle("/protected", middlewares(ProtectedHandler))

	fmt.Println("Server starting on :3000")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		fmt.Printf("Server failed: %v", err)
	}
}

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	userId := user.GetUser(r)
	if userId.Subject == "" || userId.Username == "" {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}
	components.Protected(userId.Subject).Render(r.Context(), w)
}

// HomeHandler handles the home route
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	userId := user.GetUser(r)
	w.Header().Set("Content-Type", "text/html")
	components.Root(userId.Subject).Render(r.Context(), w)
}

func loggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("request: %s %s\n", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
