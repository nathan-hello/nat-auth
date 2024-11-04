package lib

import "errors"

var (
	ErrParsingJwt       = errors.New("internal Server Error - 10001")
	ErrInvalidToken     = errors.New("internal Server Error - 10002")
	ErrJwtNotInHeader   = errors.New("internal Server Error - 10003")
	ErrJwtNotInDb       = errors.New("internal Server Error - 10004")
	ErrJwtMethodBad     = errors.New("internal Server Error - 10005")
	ErrJwtInvalidInDb   = errors.New("internal Server Error - 10006")
	ErrJwtInsertInDb    = errors.New("internal Server Error - 10007")
	ErrJwtGetSubject    = errors.New("internal Server Error - 10008")
	ErrJwtPairInvalid   = errors.New("internal Server Error - 10009")
	ErrJwtGoodAccBadRef = errors.New("internal Server Error - 10010")
)
