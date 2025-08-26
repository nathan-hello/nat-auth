package totp

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/web"
)

func (p TotpHandler) HandlerSkip(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		p.totp_Skip_POST(w, r)
		return
	}
	w.WriteHeader(http.StatusMethodNotAllowed)
}

func (p TotpHandler) totp_Skip_POST(w http.ResponseWriter, r *http.Request) {
	web.HttpRedirect(w, r, p.Redirects.AfterTotpSkip, "/")
}
