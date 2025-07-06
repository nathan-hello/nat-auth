// stolen from: https://github.com/yitsushi/totp-cli/blob/8eb8d7cac1284c57a1416996fb0b5d0c9e002923/internal/security/otp.go
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"time"
)

const (
	mask1              = 0xf
	mask2              = 0x7f
	mask3              = 0xff
	passwordHashLength = 32
	sumByteLength      = 8

	// DefaultLength is the default length of the generated OTP code.
	DefaultLength = 6
	// DefaultTimePeriod is the default time period for the TOTP.
	DefaultTimePeriod = 30
)

// GenerateOptions is the option list for the GenerateOTPCode function.
type GenerateOptions struct {
	When       time.Time
	Token      string
	TimePeriod int64
	Length     uint
}

func (opts *GenerateOptions) normalise() {
	if opts.Length == 0 {
		opts.Length = DefaultLength
	}

	if opts.TimePeriod == 0 {
		opts.TimePeriod = DefaultTimePeriod
	}

	// Remove spaces, some providers are giving us in a readable format,
	// so they add spaces in there. If it's not removed while pasting in,
	// remove it now.
	opts.Token = strings.ReplaceAll(opts.Token, " ", "")

	// It should be uppercase always
	opts.Token = strings.ToUpper(opts.Token)
}

// GenerateOTPCode generates an N digit TOTP from the secret Token.
func GenerateTOTPCode(opts GenerateOptions) (string, int64, error) {
	opts.normalise()

	timer := uint64(math.Floor(float64(opts.When.Unix()) / float64(opts.TimePeriod)))
	remainingTime := opts.TimePeriod - opts.When.Unix()%opts.TimePeriod

	secretBytes, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(opts.Token)
	if err != nil {
		return "", 0, err
	}

	buf := make([]byte, sumByteLength)
	mac := hmac.New(sha256.New, secretBytes) // default to sha256 because 1 is insecure and 512 isn't needed

	binary.BigEndian.PutUint64(buf, timer)
	_, _ = mac.Write(buf)
	sum := mac.Sum(nil)

	// http://tools.ietf.org/html/rfc4226#section-5.4
	offset := sum[len(sum)-1] & mask1
	value := int64(((int(sum[offset]) & mask2) << 24) |
		((int(sum[offset+1] & mask3)) << 16) |
		((int(sum[offset+2] & mask3)) << 8) |
		(int(sum[offset+3]) & mask3))

	//nolint:gosec // If the user sets a size that high to get an overflow, it's on them.
	modulo := int32(value % int64(math.Pow10(int(opts.Length))))

	format := fmt.Sprintf("%%0%dd", opts.Length)

	return fmt.Sprintf(format, modulo), remainingTime, nil
}

func GenerateSecret() (string, error) {
	secret := make([]byte, passwordHashLength)
	if _, err := rand.Read(secret); err != nil {
		return "", err
	}
	return strings.ToUpper(
		base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret),
	), nil
}

func CheckTOTP(code, secret string) error {
	now := time.Now().UTC()
	opts := GenerateOptions{
		Token:      secret,
		When:       now,
		TimePeriod: DefaultTimePeriod,
		Length:     DefaultLength,
	}

	// Allow two steps of clock drift in either direction.
	for step := -2; step <= 2; step++ {
		checkOpts := opts
		checkOpts.When = now.Add(time.Duration(step*int(DefaultTimePeriod)) * time.Second)

		expected, _, err := GenerateTOTPCode(checkOpts)
		if err != nil {
			return err
		}

		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return nil
		}
	}
	return fmt.Errorf("otp mismatch")
}
