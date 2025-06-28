package httpwr

import (
	"context"
	"log"
	"net/http"

	"github.com/nathan-hello/nat-auth/auth"
)

type ClaimsContextType struct{}

var ClaimsContextKey = ClaimsContextType{}

func InjectClaimsOnValidToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		access, ok := ValidateJwtOrDelete(w, r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		claims, err := auth.ParseToken(access)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		if claims == nil {
			log.Println("claims was nil")
			next.ServeHTTP(w, r)
			return

		}
		wrapReq := r.WithContext(context.WithValue(r.Context(), ClaimsContextKey, claims))
		next.ServeHTTP(w, wrapReq)
	})
}
