package storage

import "time"

type StorageAdapter interface {
	Set(key string, val []byte, expiry time.Time) error
	Get(key string) ([]byte, error)
	Del(key string) error
	Scan(pattern string, ch chan []byte) error
}
