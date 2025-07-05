package storage

type DbPassword interface {
	InsertUser(username string, password string, subject string) error
	SelectSubjectByUsername(username string) (string, error)
	SelectPasswordByUsername(username string) (string, error)
}
