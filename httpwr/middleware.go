package httpwr

import (
	"context"
	"net/http"

	"github.com/nathan-hello/nat-auth/auth"
	"github.com/nathan-hello/nat-auth/utils"
)


func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		utils.Log("http-logger").Debug("request: %s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

func VerifyJwtAndInjectUserId(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		access, _, ok := ValidateRefreshOrDeleteTokenFromCookies(w, r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		claims, err := auth.ParseToken(access)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		wrapReq := r.WithContext(context.WithValue(r.Context(), auth.UserIdContextKey, claims.UserId))
		next.ServeHTTP(w, wrapReq)
	})
}
