package auth

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/nathan-hello/nat-auth/utils"
)

type CustomClaims struct {
	jwt.RegisteredClaims
	UserId  string `json:"sub"`
	JwtType string `json:"jwt_type"`
	Family  string `json:"family"`
}

type JwtParams struct {
	UserId string `json:"sub"`
	Family string `json:"family"`
}

func NewTokenPair(j JwtParams) (string, string, string, error) {
	if j.Family == "" {
		fam, err := utils.NewUUID()
		if err != nil {
			return "", "", "", err
		}
		j.Family = fam
	}

	ac := jwt.MapClaims{
		"exp":      time.Now().Add(utils.LocalConfig().AccessExpiry).Unix(),
		"iat":      time.Now().Unix(),
		"iss":      "nat-auth",
		"sub":      j.UserId,
		"jwt_type": "access_token",
		"family":   j.Family,
	}

	access := jwt.NewWithClaims(jwt.SigningMethodHS256, &ac)

	as, err := access.SignedString([]byte(utils.LocalConfig().Secret))
	if err != nil {
		return "", "", "", err
	}

	rc := jwt.MapClaims{
		"exp":      time.Now().Add(utils.LocalConfig().RefreshExpiry).Unix(),
		"iat":      time.Now().Unix(),
		"iss":      "nat-auth",
		"sub":      j.UserId,
		"jwt_type": "refresh_token",
		"family":   j.Family,
	}

	refresh := jwt.NewWithClaims(jwt.SigningMethodHS256, &rc)
	rs, err := refresh.SignedString([]byte(utils.LocalConfig().Secret))
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
			return []byte(utils.LocalConfig().Secret), nil
		})

	if err != nil {
		return claims, err
	}

	if !token.Valid {
		return claims, ErrJwtInvalid
	}

	if claims.UserId == "" {
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
	access, refresh, _, err := NewTokenPair(JwtParams{UserId: refreshClaims.UserId, Family: refreshClaims.Family})
	if err != nil {
		return "", "", err
	}

	return access, refresh, nil
}
