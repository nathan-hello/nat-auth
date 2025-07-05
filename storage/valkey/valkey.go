package valkey

import (
	"context"
	"strings"

	"github.com/valkey-io/valkey-go"

	"github.com/nathan-hello/nat-auth/utils"
)

var US = "\x1f"

type VK struct {
	Client valkey.Client
}

func (vk *VK) InitDb(addr string) {
	var err error
	vk.Client, err = valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}})
	if err != nil {
		panic(err)
	}
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
		utils.Log("valkey").Error("InsertFamily: could not set password: %#v", err)
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
		utils.Log("valkey").Error("InvalidateUser: got error when scanning for key %s err: %#v err.Error(): %s", joined, err, err.Error())
		return err
	}
	for _, entry := range entries {
		key, err := entry.ToString()
		if err != nil {
			utils.Log("valkey").Error("InvalidateUser: could not iterate over family entry %v err: %#v, err.Error(): %s", entry, err, err.Error())
			return err
		}
		if err := vk.InsertFamily(key, userId, false); err != nil {
			utils.Log("valkey").Error("InvalidateUser: could not insertfamily key %v err: %#v, err.Error(): %s", key, err, err.Error())
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
		utils.Log("valkey").Error("SelectFamily: could not select family for userId: %s: err: %#v err.Error(): %s", userId, err, err.Error())
		return false
	}

	var val bool

	switch valid {
	case "true":
		val = true
	case "false":
		val = false
	default:
		utils.Log("valkey").Error("SelectFamily: family was a non-boolean value @ key: %s value: %s", joined, valid)
	}

	return val
}

func (vk *VK) InsertUser(username string, password string, subject string) error {
	ctx := context.Background()

	joined := strings.Join([]string{"username", username, "password"}, US)
	err := vk.Client.Do(ctx, vk.Client.B().Set().Key(joined).Value(password).Nx().Build()).Error()
	if err != nil {
		utils.Log("valkey").Error("InsertUser: could not set password: %#v", err)
		return err
	}
	joined = strings.Join([]string{"username", username, "subject"}, US)
	err = vk.Client.Do(ctx, vk.Client.B().Set().Key(joined).Value(subject).Nx().Build()).Error()
	if err != nil {
		utils.Log("valkey").Error("InsertUser: could not set subject: %#v", err)
		return err
	}
	return nil
}

func (vk *VK) SelectSubjectByUsername(username string) (string, error) {
	joined := strings.Join([]string{"username", username, "subject"}, US)
	ctx := context.Background()

	subject, err := vk.Client.Do(ctx, vk.Client.B().Get().Key(joined).Build()).ToString()
	if err != nil {
		utils.Log("valkey").Error("SelectSubjectByUsername: could not find userid for username %s err %#v err.Error(): %s", username, err, err.Error())
		return "", err
	}

	return subject, nil
}

func (vk *VK) SelectPasswordByUsername(username string) (string, error) {
	joined := strings.Join([]string{"username", username, "password"}, US)
	ctx := context.Background()

	pass, err := vk.Client.Do(ctx, vk.Client.B().Get().Key(joined).Build()).ToString()
	if err != nil {
		utils.Log("valkey").Error("SelectPasswordByUsername: could not find password for username %s err %#v err.Error(): %s", username, err, err.Error())
		return "", err
	}

	return pass, nil
}
