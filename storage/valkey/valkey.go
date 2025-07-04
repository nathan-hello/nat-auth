package valkey

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/nathan-hello/nat-auth/storage"
	"github.com/nathan-hello/nat-auth/utils"
)

var US = "\x1f"

type VK struct {
	Client net.Conn
}

func buildSetCommand(key string, val []byte, expiry *time.Duration) []byte {
	args := [][]byte{
		[]byte("SET"),
		[]byte(key),
		val,
	}

	if expiry != nil {
		str := strconv.FormatInt(int64(expiry.Seconds()), 10)
		args = append(args, []byte("EX"), []byte(str))
	}

	var cmd []byte
	cmd = fmt.Appendf(cmd, "*%d\r\n", len(args))

	for _, arg := range args {
		cmd = fmt.Appendf(cmd, "*%d\r\n", len(arg))
		cmd = append(cmd, arg...)
		cmd = append(cmd, []byte("\r\n")...)
	}
	return cmd
}

func (vk *VK) set(key []string, val []byte) error {
	return vk.setWithExpiry(key, val, 0)
}

func (vk *VK) setWithExpiry(key []string, val []byte, expiry time.Duration) error {
	joined := strings.Join(key, US)

	_, err := vk.Client.Write(buildSetCommand(joined, val, &expiry))
	if err != nil {
		return err
	}
	var buf []byte
	_, err = vk.Client.Read(buf)
	if err != nil {
		return err
	}
	if strings.HasPrefix(string(buf), "(error)") {
		return errors.New((string(buf)))
	}
	return nil
}

func (vk *VK) get(key []string) ([]byte, error) {
	joined := strings.Join(key, US)

	_, err := fmt.Fprintf(vk.Client, "*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n", len(joined), joined)
	if err != nil {
		return nil, err
	}
	var buf []byte
	_, err = vk.Client.Read(buf)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(string(buf), "(nil)") {
		return nil, errors.New("row does not exist")
	}
	if strings.HasPrefix(string(buf), "(error)") {
		return nil, errors.New((string(buf)))
	}
	return buf, nil
}

func (vk *VK) del(key []string) error {
	joined := strings.Join(key, US)

	_, err := fmt.Fprintf(vk.Client, "*2\r\n$3\r\nDEL\r\n$%d\r\n%s\r\n", len(joined), joined)
	if err != nil {
		return err
	}
	var buf []byte
	_, err = vk.Client.Read(buf)
	if err != nil {
		return err
	}
	if strings.HasPrefix(string(buf), "(nil)") {
		return errors.New("row does not exist")
	}
	if strings.HasPrefix(string(buf), "(error)") {
		return errors.New((string(buf)))
	}
	return nil
}

func (vk *VK) scan(pattern []string) chan storage.ScanResult {
	joined := strings.Join(pattern, US)

	ch := make(chan storage.ScanResult, 1)
	defer close(ch)

	cursor := "0"
	r := bufio.NewReader(vk.Client)

	iter := storage.ScanResult{}
	cmd := fmt.Sprintf("*4\r\n$4\r\nSCAN\r\n$%d\r\n%s\r\n$5\r\nMATCH\r\n$%d\r\n%s\r\n",
		len(cursor), cursor, len(joined), joined)
	_, err := vk.Client.Write([]byte(cmd))
	if err != nil {
		iter.Error = err
		ch <- iter
		return ch
	}

	go func() {
		for cursor != "0" {
			line, err := r.ReadBytes('\n')
			if err != nil {
				iter.Error = err
				ch <- iter
				return
			}
			if !bytes.HasPrefix(line, []byte("*2")) {
				iter.Error = fmt.Errorf("unexpected response: %s", line)
				ch <- iter
				return
			}

			r.ReadBytes('\n')
			cursorLine, _ := r.ReadBytes('\n')
			cursor = strings.TrimSpace(string(cursorLine))

			r.ReadBytes('\n')
			for {
				peek, _ := r.Peek(1)
				if peek[0] != '$' {
					break
				}
				r.ReadBytes('\n')
				key, _ := r.ReadBytes('\n')
				iter.Data = bytes.TrimSpace(key)
				ch <- iter
			}
		}
	}()
	return ch
}

func (vk *VK) InsertUser(username string, password []byte, subject string) error {
	err := vk.set([]string{"username", username, "subject"}, []byte(subject))
	if err != nil {
		utils.Log("valkey").Error("InsertUser: could not set subject: %#v", err)
		return err
	}
	err = vk.set([]string{"username", username, "password"}, password)
	if err != nil {
		utils.Log("valkey").Error("InsertUser: could not set password: %#v", err)
		return err
	}
	return nil
}

func (vk *VK) SelectSubjectByUsername(username string) (string, error) {
	subject, err := vk.get([]string{"username", username, "subject"})
	if err != nil {
		return "", err
	}
	if len(subject) == 0 {
		utils.Log("valkey").Error("SelectSubjectByUsername: subject is empty")
		return "", errors.New("subject is empty")
	}

	return string(subject), nil
}

func (vk *VK) SelectPasswordByUsername(username string) ([]byte, error) {
	password, err := vk.get([]string{"username", username, "password"})
	if err != nil {
		utils.Log("valkey").Error("SelectPasswordByUsername: could not get password: %#v", err)
		return nil, err
	}
	return password, nil
}
