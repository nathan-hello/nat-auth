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
	user := r.Context().Value(AuthContextKey)
	if user == nil {
		return AuthContext{Valid: false}
	}
	userParsed, ok := user.(AuthContext)
	if !ok {
		return AuthContext{Valid: false}
	}
	userParsed.Valid = true
	return userParsed
}
