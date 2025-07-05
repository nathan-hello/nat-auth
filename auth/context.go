package auth

import (
	"net/http"
)

type UserIdContextType struct{}

var UserIdContextKey = UserIdContextType{}

func GetUserId(r *http.Request) string {
	userid := r.Context().Value(UserIdContextKey).(string)
	return userid
}

