package storage

type DB interface {
	InitDb(addr string)
	InsertUser(username string, password string, subject string) error
	SelectSubjectByUsername(username string) (string, error)
	SelectPasswordByUsername(username string) (string, error)
}
