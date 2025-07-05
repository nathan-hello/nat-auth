package httpwr

import "net/http"

func Redirect(w http.ResponseWriter, r *http.Request, redirectFunc func(r *http.Request) string, defaultRoute string) bool {
	if route := redirectFunc(r); route != "" {
		w.Header().Set("HX-Redirect", route)
		return true
	}

	if defaultRoute != "" {
		w.Header().Set("HX-Redirect", defaultRoute)
		return true
	}

	return false

}
