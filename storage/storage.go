package storage



type StorageAdapter interface {
  Get(key []string) map[string]any
  Remove(key []string)
  Insert(key []string, value []byte, expiry time.Time)
  Scan(prefix []string) AsyncIterable<[string[], any]>
}

