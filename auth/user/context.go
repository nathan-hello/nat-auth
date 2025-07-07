package user

import (
	"net/http"
)

type AuthContextType struct{}

var AuthContextKey = AuthContextType{}

type AuthContext struct {
	Subject  string
	Username string
	Valid    bool
}

func GetUser(r *http.Request) AuthContext {
	userId := r.Context().Value(AuthContextKey)
	if userId == nil {
		return AuthContext{Valid: false}
	}
	user, ok := userId.(AuthContext)
	if !ok {
		return AuthContext{Valid: false}
	}
	user.Valid = true
	return user
}
