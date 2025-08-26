package totp

import (
	"net/http"

	"github.com/nathan-hello/nat-auth/storage"
)

type TotpHandler struct {
	Issuer    string
	Database  storage.DbTotp
	Ui        TotpUi
	SecretKey string
	Redirects TotpRedirects
}

type TotpFormState struct {
	Errors []error
}

type TotpUi struct {
	HtmlPageTotp func(r *http.Request, state TotpFormState, qr []byte, skipRedirectUrl string, totpSecret string) []byte
}

type RedirectFunc func(*http.Request) string

type TotpRedirects struct {
	AfterTotpVerification RedirectFunc
	AfterTotpSkip         RedirectFunc
}
