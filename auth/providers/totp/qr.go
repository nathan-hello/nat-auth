package totp

import qrcode "github.com/skip2/go-qrcode"

func QRTOTP(secret string) ([]byte, error) {
	var png []byte
	png, err := qrcode.Encode(secret, qrcode.Medium, 256)
	if err != nil {
		return nil, err
	}
	return png, nil
}
