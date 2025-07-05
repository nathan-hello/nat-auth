package storage

type DbJwt interface {
	NewUserId() (string, error)
	InsertFamily(userId, family string, value bool) error
	SelectFamily(userId, family string) bool
	InvalidateUser(userId string) error
}

type DbPassword interface {
	DbJwt
	InsertUser(username string, password string, subject string) error
	SelectSubjectByUsername(username string) (string, error)
	SelectPasswordByUsername(username string) (string, error)
}
