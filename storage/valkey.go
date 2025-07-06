package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"strings"

	"github.com/nathan-hello/nat-auth/logger"
	"github.com/valkey-io/valkey-go"
)

var US = "\x1f"

type VK struct {
	Client valkey.Client
}

func NewValkey(addr string) *VK {
	var err error
	client, err := valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}})
	if err != nil {
		panic(err)
	}
	return &VK{Client: client}
}

func (vk *VK) InsertFamily(userId, family string, value bool) error {
	ctx := context.Background()
	joined := strings.Join([]string{"jwt", "subject", userId}, US)

	var val string
	if value {
		val = "true"
	} else {
		val = "false"
	}

	err := vk.Client.Do(ctx, vk.Client.B().Hset().Key(joined).FieldValue().FieldValue(family, val).Build()).Error()
	if err != nil {
		logger.Log("valkey").Error("InsertFamily: could not set password: %#v", err)
		return err
	}
	return nil
}

func (vk *VK) InvalidateUser(userId string) error {
	var cursor uint64 = 0
	ctx := context.Background()
	joined := strings.Join([]string{"jwt", "subject", userId}, US)
	entries, err := vk.Client.Do(ctx, vk.Client.B().Hscan().Key(joined).Cursor(cursor).Novalues().Build()).ToArray()
	if err != nil {
		logger.Log("valkey").Error("InvalidateUser: got error when scanning for key %s err: %#v err.Error(): %s", joined, err, err.Error())
		return err
	}
	for _, entry := range entries {
		key, err := entry.ToString()
		if err != nil {
			logger.Log("valkey").Error("InvalidateUser: could not iterate over family entry %v err: %#v, err.Error(): %s", entry, err, err.Error())
			return err
		}
		if err := vk.InsertFamily(key, userId, false); err != nil {
			logger.Log("valkey").Error("InvalidateUser: could not insertfamily key %v err: %#v, err.Error(): %s", key, err, err.Error())
			return err
		}
	}
	return nil
}

func (vk *VK) SelectFamily(userId, family string) bool {
	ctx := context.Background()
	joined := strings.Join([]string{"jwt", "subject", userId, "family", family}, US)

	valid, err := vk.Client.Do(ctx, vk.Client.B().Get().Key(joined).Build()).ToString()
	if err != nil {
		logger.Log("valkey").Error("SelectFamily: could not select family for userId: %s: err: %#v err.Error(): %s", userId, err, err.Error())
		return false
	}

	var val bool
	switch valid {
	case "true":
		val = true
	case "false":
		val = false
	default:
		logger.Log("valkey").Error("SelectFamily: family was a non-boolean value @ key: %s value: %s", joined, valid)
	}

	return val
}

func (vk *VK) InsertSubject(username string, subject string) error {
	ctx := context.Background()

	joined := strings.Join([]string{"username", username, "subject"}, US)
	err := vk.Client.Do(ctx, vk.Client.B().Set().Key(joined).Value(subject).Build()).Error()
	if err != nil {
		logger.Log("valkey").Error("InsertUser: could not set subject: %#v", err)
		return err
	}
	return nil
}

func (vk *VK) InsertSecret(subject, secret string) error {
	ctx := context.Background()

	joined := strings.Join([]string{"subject", subject, "secret"}, US)
	err := vk.Client.Do(ctx, vk.Client.B().Set().Key(joined).Value(secret).Build()).Error()
	if err != nil {
		logger.Log("valkey").Error("InsertUser: could not set TOTP secret: %#v", err)
		return err
	}
	return nil
}

func (vk *VK) SelectSecret(subject string) (string, error) {
	joined := strings.Join([]string{"subject", subject, "secret"}, US)
	ctx := context.Background()

	subject, err := vk.Client.Do(ctx, vk.Client.B().Get().Key(joined).Build()).ToString()
	if err != nil {
		logger.Log("valkey").Error("SelectSubjectByUsername: could not find TOTP secret for subject %s err %#v err.Error(): %s", subject, err, err.Error())
		return "", err
	}

	return subject, nil
}

func (vk *VK) InsertUser(username string, password string) error {
	ctx := context.Background()

	joined := strings.Join([]string{"username", username, "password"}, US)
	err := vk.Client.Do(ctx, vk.Client.B().Set().Key(joined).Value(password).Build()).Error()
	if err != nil {
		logger.Log("valkey").Error("InsertUser: could not set password: %#v", err)
		return err
	}
	return nil
}

func (vk *VK) SelectSubjectByUsername(username string) (string, error) {
	joined := strings.Join([]string{"username", username, "subject"}, US)
	ctx := context.Background()

	subject, err := vk.Client.Do(ctx, vk.Client.B().Get().Key(joined).Build()).ToString()
	if err != nil {
		logger.Log("valkey").Error("SelectSubjectByUsername: could not find userid for username %s err %#v err.Error(): %s", username, err, err.Error())
		return "", err
	}

	return subject, nil
}

func (vk *VK) SelectPasswordByUsername(username string) (string, error) {
	joined := strings.Join([]string{"username", username, "password"}, US)
	ctx := context.Background()

	pass, err := vk.Client.Do(ctx, vk.Client.B().Get().Key(joined).Build()).ToString()
	if err != nil {
		logger.Log("valkey").Error("SelectPasswordByUsername: could not find password for username %s err %#v err.Error(): %s", username, err, err.Error())
		return "", err
	}

	return pass, nil
}

// Taken from github.com/google/uuid/version4.go
func (vk *VK) NewUserId() (string, error) {
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

// Taken from github.com/google/uuid/version4.go
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
