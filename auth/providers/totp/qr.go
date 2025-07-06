package totp

import (
	"encoding/base64"

	qrcode "github.com/skip2/go-qrcode"
)

func QRTOTP(secret string) ([]byte, error) {
	var png []byte
	png, err := qrcode.Encode(secret, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, base64.StdEncoding.EncodedLen(len(png)))
	base64.StdEncoding.Encode(dst, png)
	return dst, nil
}
