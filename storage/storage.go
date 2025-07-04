package storage

import "time"

type ScanResult struct {
	Data  []byte
	Error error
}

type StorageAdapter interface {
	Set(key []string, val []byte) error
	SetWithExpiry(key []string, val []byte, expiry time.Duration) error
	Get(key []string) ([]byte, error)
	Del(key []string) error
	Scan(pattern []string) chan ScanResult
}
