package main

import (
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nathan-hello/nat-auth/auth/providers"
	"github.com/nathan-hello/nat-auth/httpwr"
	"github.com/nathan-hello/nat-auth/storage/valkey"
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
	})

	p := providers.PasswordHandler{
		UsernameValidate: nil,
		Database:         &store,
		RedirectAfterSignIn: func(r *http.Request) string {
			return "/"
		},
		RedirectAfterSignUp: func(r *http.Request) string {
			return "/"
		},
		Ui: providers.PasswordUiDefault,
	}

	http.Handle("/auth/signup", httpwr.Logger(http.HandlerFunc(p.RegisterHandler)))
	http.Handle("/auth/signin", httpwr.Logger(http.HandlerFunc(p.AuthorizeHandler)))

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
