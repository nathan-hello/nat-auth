package web

import (
	"context"
	"net/http"

	"github.com/justinas/alice"
	"github.com/nathan-hello/nat-auth/auth"
)

// This middleware handles the following cases:
//   - If User's access and refresh are both valid, insert AuthContext struct into request context
//   - If User's access is invalid and refresh is valid, refresh JWTs
//   - If User's access and refresh are both invalid, delete JWTs
func MiddlewareAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access, _, ok := CookieRefreshOrDelete(w, r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		claims, err := ParseToken(access)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		val := auth.AuthContext{
			Subject:  claims.Subject,
			Username: claims.UserName,
			Valid:    true,
		}

		wrapReq := r.WithContext(context.WithValue(r.Context(), auth.AuthContextKey, val))
		next.ServeHTTP(w, wrapReq)
	})
}


// This returned an alice.Constructor instead of
// being an alice.Constructor because it requires an argument (path string).
func RejectSubroute(path string) alice.Constructor {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != path {
				http.NotFound(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
