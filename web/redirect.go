package web

import "net/http"

func HttpRedirect(w http.ResponseWriter, r *http.Request, redirectFunc func(r *http.Request) string, defaultRoute string) bool {
	var route string

	if redirectFunc != nil {
		route = redirectFunc(r)
	} else if defaultRoute != "" {
		route = defaultRoute
	}
	if route == "" {
		return false
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", route)
		return true
	} else {
		http.Redirect(w, r, route, http.StatusSeeOther)
		return true
	}
}
