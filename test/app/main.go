package main

import (
	"context"
	"net"
	"net/http"

	"github.com/nathan-hello/nat-auth/auth/providers"
	"github.com/nathan-hello/nat-auth/httpwr"
	"github.com/nathan-hello/nat-auth/storage/valkey"
)

func main() {
	conn, err := net.Dial("tcp", "127.0.0.1:6379")
	if err != nil {
		panic(err)
	}

	store := valkey.VK{
		Client: conn,
	}

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

	http.ListenAndServe(":3000", nil)
}
