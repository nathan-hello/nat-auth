package web

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type CustomClaims struct {
	jwt.RegisteredClaims
	JwtType  string `json:"jwt_type"`
	Family   string `json:"family"`
	UserName string `json:"user"`
}

type JwtParams struct {
	Subject  string `json:"sub"`
	Family   string `json:"family"`
	UserName string `json:"user"`
}

func NewTokenPair(j JwtParams) (string, string, string, error) {
	if j.Family == "" {
		fam, err := newUuid()
		if err != nil {
			return "", "", "", err
		}
		j.Family = fam
	}

	ac := jwt.MapClaims{
		"exp":      time.Now().Add(JwtConfig().AccessExpiry).Unix(),
		"iat":      time.Now().Unix(),
		"iss":      "nat-auth",
		"sub":      j.Subject,
		"jwt_type": "access_token",
		"family":   j.Family,
		"user":     j.UserName,
	}

	access := jwt.NewWithClaims(jwt.SigningMethodHS256, &ac)

	as, err := access.SignedString([]byte(JwtConfig().Secret))
	if err != nil {
		return "", "", "", err
	}

	rc := jwt.MapClaims{
		"exp":      time.Now().Add(JwtConfig().RefreshExpiry).Unix(),
		"iat":      time.Now().Unix(),
		"iss":      "nat-auth",
		"sub":      j.Subject,
		"jwt_type": "refresh_token",
		"family":   j.Family,
		"user":     j.UserName,
	}

	refresh := jwt.NewWithClaims(jwt.SigningMethodHS256, &rc)
	rs, err := refresh.SignedString([]byte(JwtConfig().Secret))
	if err != nil {
		return "", "", "", err
	}
	return as, rs, j.Family, nil
}

func ParseToken(t string) (CustomClaims, error) {
	claims := CustomClaims{}
	token, err := jwt.ParseWithClaims(
		t,
		&claims,
		func(token *jwt.Token) (any, error) {
			ok := token.Method.Alg() == "HS256"
			if !ok {
				// this error will not show unless logged because
				// the jwt library wraps this error
				return nil, ErrJwtMethodBad
			}
			return []byte(JwtConfig().Secret), nil
		})

	if err != nil {
		return claims, err
	}

	if !token.Valid {
		return claims, ErrJwtInvalid
	}

	if claims.Subject == "" {
		return claims, ErrJwtInvalid
	}

	if claims.UserName == "" {
		return claims, ErrJwtInvalid
	}

	return claims, nil
}

func ParseOrRefreshToken(a string, r string) (string, string, error) {

	_, err := ParseToken(a)
	// if access is good, let's just refresh
	if err == nil {
		_, err = ParseToken(r)
		// if refresh and access are good, return to sender
		if err == nil {
			return a, r, nil
		}
		// if access is good but refresh is bad, we don't refresh based off
		// of access tokens, so it's better to just error and reauth
		return "", "", ErrJwtGoodAccBadRef
	}

	// even if access was bad, maybe the refresh is good
	refreshClaims, err := ParseToken(r)
	if err != nil {
		if err == ErrJwtInvalidInDb {
			return "", "", ErrJwtInvalidInDb
		}
		return "", "", err
	}

	// sweet, a good refresh jwt. let's make a new pair using the OLD family.
	access, refresh, _, err := NewTokenPair(JwtParams{Subject: refreshClaims.Subject, Family: refreshClaims.Family, UserName: refreshClaims.UserName})
	if err != nil {
		return "", "", err
	}

	return access, refresh, nil
}

// Taken from github.com/google/uuid/version4.go
func newUuid() (string, error) {
	var uuid [16]byte
	_, err := io.ReadFull(rand.Reader, uuid[:])
	if err != nil {
		return "", err
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant is 10
	var buf [36]byte
	encodeHex(buf[:], uuid)
	return string(buf[:]), nil
}

// Taken from github.com/google/uuid/version4.go
func encodeHex(dst []byte, uuid [16]byte) {
	hex.Encode(dst, uuid[:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], uuid[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], uuid[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], uuid[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:], uuid[10:])
}
