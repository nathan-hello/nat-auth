package storage

type DbTotp interface {
	InsertSecret(userId, secret string) error
	SelectSecret(userId, secret string) (string, error)
}

type DbJwt interface {
	NewUserId() (string, error)
	InsertFamily(userId, family string, value bool) error
	SelectFamily(userId, family string) bool
	InvalidateUser(userId string) error
}

type DbPassword interface {
	DbTotp
	DbJwt
	InsertUser(username string, password string) error
	InsertSubject(username string, subject string) error
	SelectSubjectByUsername(username string) (string, error)
	SelectPasswordByUsername(username string) (string, error)
}
