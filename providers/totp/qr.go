package totp

import (
	"encoding/base64"
	"fmt"
	"net/url"

	qrcode "github.com/skip2/go-qrcode"
)

func QRTOTP(secret, username, issuer string) ([]byte, error) {
	var png []byte
	label := fmt.Sprintf("%s:%s", issuer, username)
	encodedLabel := url.PathEscape(label)

	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA256")
	q.Set("digits", fmt.Sprintf("%d", DefaultLength))
	q.Set("period", fmt.Sprintf("%d", DefaultTimePeriod))
	uri := fmt.Sprintf("otpauth://totp/%s?%s", encodedLabel, q.Encode())

	png, err := qrcode.Encode(uri, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(png)))
	base64.StdEncoding.Encode(dst, png)
	return dst, nil
}
