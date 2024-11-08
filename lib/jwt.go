package lib

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type CustomClaims struct {
	jwt.RegisteredClaims
	UserId   string `json:"sub"`
	Username string `json:"username"`
	JwtType  string `json:"jwt_type"`
	Family   string `json:"family"`
}

type JwtParams struct {
	Username string
	UserId   string
	Family   string
}

func NewTokenPair(j *JwtParams) (string, string, error) {
	if j.Family == "" {
		j.Family = uuid.New().String()
	}
	ac := jwt.MapClaims{
		"exp":      time.Now().Add(LocalConfig().AccessExpiry).Unix(),
		"iat":      time.Now().Unix(),
		"iss":      "no-magic-stack-example",
		"sub":      j.UserId,
		"username": j.Username,
		"jwt_type": "access_token",
		"family":   j.Family,
	}

	access := jwt.NewWithClaims(jwt.SigningMethodHS256, &ac)

	as, err := access.SignedString([]byte(LocalConfig().Secret))
	if err != nil {
		return "", "", err
	}

	rc := jwt.MapClaims{
		"exp":      time.Now().Add(LocalConfig().RefreshExpiry).Unix(),
		"iat":      time.Now().Unix(),
		"iss":      "no-magic-stack-example",
		"sub":      j.UserId,
		"username": j.Username,
		"jwt_type": "refresh_token",
		"family":   j.Family,
	}

	refresh := jwt.NewWithClaims(jwt.SigningMethodHS256, &rc)
	rs, err := refresh.SignedString([]byte(LocalConfig().Secret))
	if err != nil {
		return "", "", err
	}
	return as, rs, nil
}

func ParseToken(t string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(
		t,
		&CustomClaims{},
		func(token *jwt.Token) (interface{}, error) {
			ok := token.Method.Alg() == "HS256"
			if !ok {
				// this error will not show unless logged because
				// the jwt library wraps this error
				return nil, ErrJwtMethodBad
			}
			return []byte(LocalConfig().Secret), nil
		})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, err
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return nil, ErrParsingJwt
	}

	return claims, nil

}

func ValidateJwtFromString(t string) error {
	token, err := jwt.Parse(
		t, func(token *jwt.Token) (interface{}, error) {
			ok := token.Method.Alg() == "HS256"
			if !ok {
				// this error will not show unless logged because
				// the jwt library wraps this error
				return nil, ErrJwtMethodBad
			}
			return []byte(LocalConfig().Secret), nil
		})

	if err != nil {
		return ErrParsingJwt
	}

	if !token.Valid {
		return ErrInvalidToken
	}
	return nil
}

func NewPairFromRefresh(r string) (string, string, error) {
	claims, err := ParseToken(r)
	if err != nil {
		return "", "", err
	}

	access, refresh, err := NewTokenPair(&JwtParams{UserId: claims.UserId, Username: claims.Username})
	if err != nil {
		return "", "", err
	}
	return access, refresh, nil

}

func ValidatePairOrRefresh(a string, r string) (string, string, error) {

	err := ValidateJwtFromString(a)
	// if access is good, let's just refresh
	if err == nil {
		err = ValidateJwtFromString(r)
		// if refresh and access are good, return to sender
		if err == nil {
			return a, r, nil
		}
		// if access is good but refresh is bad, we don't refresh based off
		// of access tokens, so it's better to just error and reauth
		return "", "", ErrJwtGoodAccBadRef
	}

	// even if access was bad, maybe the refresh is good
	// err = ValidateJwtFromString(r)
	// if err != nil {
	// 	if err == utils.ErrJwtInvalidInDb {
	// 		return "", "", DbInvalidateJwtFamily(r)
	// 	}
	// 	return "", "", err
	// }

	// sweet, a good refresh jwt. let's make a new pair
	access, refresh, err := NewPairFromRefresh(r)
	if err != nil {
		return "", "", err
	}

	return access, refresh, nil
}
