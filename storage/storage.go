package storage

import "time"

type StorageAdapter interface {
	Set(key []string, val []byte) error
	SetWithExpiry(key []string, val []byte, expiry time.Duration) error
	Get(key []string) ([]byte, error)
	Del(key string) error
	Scan(pattern string, ch chan []byte) error
}
