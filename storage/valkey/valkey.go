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
)

type VK struct {
	Addr string
}

func buildSetCommand(key string, val []byte, expiry time.Duration) []byte {
	args := [][]byte{
		[]byte("SET"),
		[]byte(key),
		val,
		[]byte("EX"),
	}

	str := strconv.FormatInt(int64(expiry.Seconds()), 10)
	args = append(args, []byte(str))
	var cmd []byte
	cmd = fmt.Appendf(cmd, "*%d\r\n", len(args))

	for _, arg := range args {
		cmd = fmt.Appendf(cmd, "*%d\r\n", len(arg))
		cmd = append(cmd, arg...)
		cmd = append(cmd, []byte("\r\n")...)
	}
	return cmd
}

func (vk *VK) Set(key string, val []byte, expiry time.Duration) error {
	c, err := net.DialTCP(vk.Addr, nil, nil)	
	if err != nil {
		return err
	}
	defer c.Close()

	_, err = c.Write(buildSetCommand(key, val, expiry))
	if err != nil {
		return err
	}
	var buf []byte
	_, err = c.Read(buf)
	if err != nil {
		return err
	}
	return nil
}

func (vk *VK) Get(key string) ([]byte, error) {
	c, err := net.DialTCP(vk.Addr, nil, nil)	
	if err != nil {
		return nil, err
	}
	defer c.Close()

	_, err = fmt.Fprintf(c, "*2\r\n$3\r\nGET\r\n$%d\r\n%s\r\n", len(key), key)
	if err != nil {
		return nil, err
	}
	var buf []byte
	_, err = c.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (vk *VK) Del(key string) error {
	c, err := net.DialTCP(vk.Addr, nil, nil)	
	if err != nil {
		return err
	}
	defer c.Close()

	_, err = fmt.Fprintf(c, "*2\r\n$3\r\nDEL\r\n$%d\r\n%s\r\n", len(key), key)
	if err != nil {
		return err
	}
	var buf []byte
	_, err = c.Read(buf)
	if err != nil {
		return err
	}
	if strings.HasPrefix(string(buf), "(error)") || strings.HasPrefix(string(buf), "(nil)") {
		return errors.New((string(buf)))
	}
	return nil
}

func (vk *VK) Scan(pattern string, ch chan []byte) error {
	c, err := net.DialTCP(vk.Addr, nil, nil)	
	if err != nil {
		return  err
	}
	defer c.Close()

	cursor := "0"
	r := bufio.NewReader(c)

	for cursor != "0" {
		cmd := fmt.Sprintf("*4\r\n$4\r\nSCAN\r\n$%d\r\n%s\r\n$5\r\nMATCH\r\n$%d\r\n%s\r\n",
			len(cursor), cursor, len(pattern), pattern)
		_, err = c.Write([]byte(cmd))
		if err != nil {
			return err
		}

		line, err := r.ReadBytes('\n')
		if err != nil {
			return err
		}
		if !bytes.HasPrefix(line, []byte("*2")) {
			return fmt.Errorf("unexpected response: %s", line)
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
			ch <- bytes.TrimSpace(key)
		}
	}
	return nil
}
