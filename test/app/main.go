package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/nathan-hello/nat-auth/auth/providers"
	"github.com/nathan-hello/nat-auth/httpwr"
	"github.com/nathan-hello/nat-auth/storage/valkey"
	"github.com/nathan-hello/nat-auth/utils"
)

func main() {
	store := valkey.VK{}
	store.Init("127.0.0.1:6379")

	p := providers.PasswordHandler{
		UsernameValidate: nil,
		Database:         &store,
		RedirectAfterSignIn: func(ctx context.Context) string {
			return "/"
		},
		RedirectAfterSignUp: func(ctx context.Context) string {
			return "/"
		},
	}

	http.Handle("/auth/signup", httpwr.Logger(http.HandlerFunc(p.RegisterHandler)))
	http.Handle("/auth/signin", httpwr.Logger(http.HandlerFunc(p.AuthorizeHandler)))

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		utils.Log("main").Info("Received shutdown signal, closing connections...")
		os.Exit(0)
	}()

	utils.Log("main").Info("Server starting on :3000")
	if err := http.ListenAndServe(":3000", nil); err != nil {
		utils.Log("main").Error("Server failed: %v", err)
	}
}
