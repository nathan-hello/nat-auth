package app

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/auth/providers/password"
	"github.com/nathan-hello/nat-auth/storage/valkey"
)

func main() {
	p := password.PasswordHandler{
		Config: password.PasswordConfig{
			UsernameValidate: nil,
			Storage: valkey.VK{},
			RedirectAfterSignIn: "/",
			RedirectAfterSignUp: "/",
		},
	}

	http.Handle("/register", )	

}
