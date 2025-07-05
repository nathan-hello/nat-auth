package auth

import (
	"net/http"
)

type UserIdContextType struct{}

var UserIdContextKey = UserIdContextType{}

func GetUserId(r *http.Request) string {
	userId := r.Context().Value(UserIdContextKey)
	if userId == nil {
		return ""
	}
	userStr, ok := userId.(string)
	if !ok {
		return ""
	}

	return userStr
}
