-- name: InsertUser :exec
INSERT INTO users (username, password) VALUES (?, ?);

-- name: SelectPasswordByUsername :one
SELECT password FROM users WHERE username = ?;

-- name: InsertSubject :exec
INSERT INTO subjects (username, subject) VALUES (?, ?);

-- name: SelectSubjectByUsername :one
SELECT subject FROM subjects WHERE username = ?;

-- name: InsertSecret :exec
INSERT OR REPLACE INTO secrets (subject, secret) VALUES (?, ?);

-- name: SelectSecret :one
SELECT secret FROM secrets WHERE subject = ?;

-- name: InsertFamily :exec
INSERT OR REPLACE INTO families (subject, family, valid) VALUES (?, ?, ?);

-- name: SelectFamily :one
SELECT valid FROM families WHERE subject = ? AND family = ?;

-- name: InvalidateUser :exec
UPDATE families SET valid = FALSE WHERE subject = ?; 