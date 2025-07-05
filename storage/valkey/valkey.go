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
		return "", err
	}

	return subject, nil
}

func (vk *VK) SelectPasswordByUsername(username string) (string, error) {
	joined := strings.Join([]string{"username", username, "password"}, US)
	ctx := context.Background()

	pass, err := vk.Client.Do(ctx, vk.Client.B().Get().Key(joined).Build()).ToString()
	if err != nil {
		return "", err
	}

	return pass, nil
}
