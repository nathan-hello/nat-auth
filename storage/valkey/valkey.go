package valkey

import (
	"context"
	"strings"

	"github.com/valkey-io/valkey-go"

	"github.com/nathan-hello/nat-auth/utils"
)

var US = "\x1f"

type VK struct {
	client valkey.Client
}

func (vk *VK) Init(addr string) {
	var err error
	vk.client, err = valkey.NewClient(valkey.ClientOption{InitAddress: []string{addr}})
	if err != nil {
		panic(err)
	}
}

func (vk *VK) InsertUser(username string, password string, subject string) error {
	ctx := context.Background()

	joined := strings.Join([]string{"username", username, "password"}, US)
	err := vk.client.Do(ctx, vk.client.B().Set().Key(joined).Value(password).Nx().Build()).Error()
	if err != nil {
		utils.Log("valkey").Error("InsertUser: could not set password: %#v", err)
		return err
	}
	joined = strings.Join([]string{"username", username, "subject"}, US)
	err = vk.client.Do(ctx, vk.client.B().Set().Key(joined).Value(subject).Nx().Build()).Error()
	if err != nil {
		utils.Log("valkey").Error("InsertUser: could not set subject: %#v", err)
		return err
	}
	return nil
}

func (vk *VK) SelectSubjectByUsername(username string) (string, error) {
	joined := strings.Join([]string{"username", username, "subject"}, US)
	ctx := context.Background()

	subject, err := vk.client.Do(ctx, vk.client.B().Get().Key(joined).Build()).ToString()
	if err != nil {
		return "", err
	}

	return subject, nil
}

func (vk *VK) SelectPasswordByUsername(username string) (string, error) {
	joined := strings.Join([]string{"username", username, "password"}, US)
	ctx := context.Background()

	pass, err := vk.client.Do(ctx, vk.client.B().Get().Key(joined).Build()).ToString()
	if err != nil {
		return "", err
	}

	return pass, nil
}
