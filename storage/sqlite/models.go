// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.29.0

package sqlite

type Family struct {
	Subject string
	Family  string
	Valid   bool
}

type Secret struct {
	Subject string
	Secret  string
}

type Subject struct {
	Username string
	Subject  string
}

type User struct {
	Username string
	Password string
}
