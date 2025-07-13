package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	natauth "github.com/nathan-hello/nat-auth"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/storage"
	"github.com/nathan-hello/nat-auth/test/app/components"
	"github.com/nathan-hello/nat-auth/ui"
	"github.com/nathan-hello/nat-auth/utils"
	"github.com/nathan-hello/nat-auth/web"
)

func main() {
	store, err := storage.NewValkey("127.0.0.1:6379", "app")
	if err != nil {
		utils.Log("create").Error("error in NewValkey: %s", err.Error())
		panic(err)
	}

	handlers, err := natauth.New(natauth.Params{
		JwtConfig:  web.PasswordJwtParams{Secret: "secret"},
		Storage:    store,
		LogWriters: []io.Writer{os.Stdout},
		Theme: ui.Theme{
			Primary: ui.ColorScheme{
				Light: "#262626",
				Dark:  "#262626",
			},
			Background: ui.ColorScheme{
				Light: "#171717",
				Dark:  "#171717",
			},
			Logo: ui.ColorScheme{
				Light: "https://reluekiss.com/favicon.svg",
				Dark:  "https://reluekiss.com/favicon.svg",
			},
			Title:   "Nat/e",
			Favicon: "https://reluekiss.com/favicon.svg",
			Radius:  "none",
			Font: ui.Font{
				Family: "Varela Round, sans-serif",
				Scale:  "1",
			},
		},
	})
	if err != nil {
		panic(err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Printf("Received shutdown signal, closing connections...")
		handlers.OnClose()
		store.Client.Close()
		fmt.Printf("Valkey client closed")
		os.Exit(0)
	}()

	http.Handle("/", handlers.Middleware(HomeHandler))
	http.Handle("/protected", handlers.Middleware(ProtectedHandler))

	fmt.Println("Server starting on :3000")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		fmt.Printf("Server failed: %v", err)
	}
}

func ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	user := auth.GetUser(r)
	if !user.Valid {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}
	components.Protected(user.Subject).Render(r.Context(), w)
}

// HomeHandler handles the home route
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	userId := auth.GetUser(r)
	w.Header().Set("Content-Type", "text/html")
	components.Root(userId.Subject).Render(r.Context(), w)
}

func loggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("request: %s %s\n", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
