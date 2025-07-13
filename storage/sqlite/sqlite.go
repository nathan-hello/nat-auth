package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"io"

	_ "github.com/mattn/go-sqlite3"
	"github.com/nathan-hello/nat-auth/utils"
)

type SQLiteDB struct {
	db      *sql.DB
	queries *Queries
}

func NewSQLiteDB(dbPath string) (*SQLiteDB, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, err
	}

	queries := New(db)
	return &SQLiteDB{db: db, queries: queries}, nil
}

func (s *SQLiteDB) Close() error {
	return s.db.Close()
}

// DbPassword interface implementation

func (s *SQLiteDB) InsertUser(username string, password string) error {
	ctx := context.Background()
	err := s.queries.InsertUser(ctx, InsertUserParams{
		Username: username,
		Password: password,
	})
	if err != nil {
		utils.Log("sqlite").Error("InsertUser: could not insert user: %#v", err)
		return err
	}
	return nil
}

func (s *SQLiteDB) SelectPasswordByUsername(username string) (string, error) {
	ctx := context.Background()
	password, err := s.queries.SelectPasswordByUsername(ctx, username)
	if err != nil {
		utils.Log("sqlite").Error("SelectPasswordByUsername: could not find password for username %s err: %#v", username, err)
		return "", err
	}
	return password, nil
}

func (s *SQLiteDB) InsertSubject(username string, subject string) error {
	ctx := context.Background()
	err := s.queries.InsertSubject(ctx, InsertSubjectParams{
		Username: username,
		Subject:  subject,
	})
	if err != nil {
		utils.Log("sqlite").Error("InsertSubject: could not insert subject: %#v", err)
		return err
	}
	return nil
}

func (s *SQLiteDB) SelectSubjectByUsername(username string) (string, error) {
	ctx := context.Background()
	subject, err := s.queries.SelectSubjectByUsername(ctx, username)
	if err != nil {
		utils.Log("sqlite").Error("SelectSubjectByUsername: could not find subject for username %s err: %#v", username, err)
		return "", err
	}
	return subject, nil
}

// DbTotp interface implementation

func (s *SQLiteDB) InsertSecret(userId, secret string) error {
	ctx := context.Background()
	err := s.queries.InsertSecret(ctx, InsertSecretParams{
		Subject: userId,
		Secret:  secret,
	})
	if err != nil {
		utils.Log("sqlite").Error("InsertSecret: could not insert TOTP secret: %#v", err)
		return err
	}
	return nil
}

func (s *SQLiteDB) SelectSecret(userId string) (string, error) {
	ctx := context.Background()
	secret, err := s.queries.SelectSecret(ctx, userId)
	if err != nil {
		utils.Log("sqlite").Error("SelectSecret: could not find TOTP secret for userId %s err: %#v", userId, err)
		return "", err
	}
	return secret, nil
}

// DbJwt interface implementation

func (s *SQLiteDB) InsertFamily(userId, family string, value bool) error {
	ctx := context.Background()
	err := s.queries.InsertFamily(ctx, InsertFamilyParams{
		Subject: userId,
		Family:  family,
		Valid:   value,
	})
	if err != nil {
		utils.Log("sqlite").Error("InsertFamily: could not insert family: %#v", err)
		return err
	}
	return nil
}

func (s *SQLiteDB) SelectFamily(userId, family string) bool {
	ctx := context.Background()
	valid, err := s.queries.SelectFamily(ctx, SelectFamilyParams{
		Subject: userId,
		Family:  family,
	})
	if err != nil {
		utils.Log("sqlite").Error("SelectFamily: could not select family for userId: %s family: %s err: %#v", userId, family, err)
		return false
	}
	return valid
}

func (s *SQLiteDB) InvalidateUser(userId string) error {
	ctx := context.Background()
	err := s.queries.InvalidateUser(ctx, userId)
	if err != nil {
		utils.Log("sqlite").Error("InvalidateUser: could not invalidate user %s err: %#v", userId, err)
		return err
	}
	return nil
}

// NewUserId generates a new UUID v4 (same implementation as valkey)
func (s *SQLiteDB) NewUserId() (string, error) {
	var uuid [16]byte
	_, err := io.ReadFull(rand.Reader, uuid[:])
	if err != nil {
		return "", err
	}
	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant is 10
	var buf [36]byte
	encodeHex(buf[:], uuid)
	return string(buf[:]), nil
}

// encodeHex is a helper function for UUID generation (same as valkey)
func encodeHex(dst []byte, uuid [16]byte) {
	hex.Encode(dst, uuid[:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], uuid[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], uuid[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], uuid[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:], uuid[10:])
}
