package totp

import (
	"encoding/base64"
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

func QRTOTP(secret, username string) ([]byte, error) {
	var png []byte
	issuer := "nat-auth"
	formated := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA256&digits=%d&period=%d",
		issuer, username, secret, issuer, DefaultLength, DefaultTimePeriod)
	png, err := qrcode.Encode(formated, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(png)))
	base64.StdEncoding.Encode(dst, png)
	return dst, nil
}
