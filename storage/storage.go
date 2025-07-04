package storage

type DB interface {
	InsertUser(username string, password []byte, subject string) error
	SelectSubjectByUsername(username string) (string, error)
	SelectPasswordByUsername(username string) ([]byte, error)
}
