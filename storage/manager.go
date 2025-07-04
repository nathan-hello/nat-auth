package storage

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/nathan-hello/nat-auth/utils"
)

// ConnectionManager handles robust Redis connections with reconnection logic
type ConnectionManager struct {
	address        string
	conn           net.Conn
	mu             sync.RWMutex
	maxRetries     int
	retryDelay     time.Duration
	connectTimeout time.Duration
}

type ReadWriteConnector interface {
	Write(data []byte) (int, error)
	Read(data []byte) (int, error)
	Fprintf(format string, args ...any) (int, error)
	GetConn() net.Conn
	Connect() error
	Close() error
}

func NewConnectionManager(address string, maxRetries int, retryDelay time.Duration, connectTimeout time.Duration) *ConnectionManager {
	cm := &ConnectionManager{
		address:        address,
		maxRetries:     maxRetries,
		retryDelay:     retryDelay,
		connectTimeout: connectTimeout,
	}
	return cm
}

// Connect establishes a connection with retry logic
func (cm *ConnectionManager) Connect() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	var lastErr error
	for i := 0; i <= cm.maxRetries; i++ {
		if i > 0 {
			utils.Log("valkey").Info("Retrying connection to %s (attempt %d/%d)", cm.address, i, cm.maxRetries)
			time.Sleep(cm.retryDelay)
		}

		conn, err := net.DialTimeout("tcp", cm.address, cm.connectTimeout)
		if err != nil {
			lastErr = err
			continue
		}

		cm.conn = conn
		utils.Log("valkey").Info("Successfully connected to %s", cm.address)
		return nil
	}

	return fmt.Errorf("failed to connect to %s after %d attempts: %w", cm.address, cm.maxRetries, lastErr)
}

// Write writes data to the connection with reconnection logic
func (cm *ConnectionManager) Write(data []byte) (int, error) {
	cm.mu.RLock()
	conn := cm.conn
	cm.mu.RUnlock()

	if conn == nil {
		if err := cm.Connect(); err != nil {
			return 0, err
		}
		cm.mu.RLock()
		conn = cm.conn
		cm.mu.RUnlock()
	}

	n, err := conn.Write(data)
	if err != nil {
		utils.Log("valkey").Error("Write error: %v", err)
		// Try to reconnect on write error
		if reconnectErr := cm.Connect(); reconnectErr != nil {
			return n, fmt.Errorf("write failed and reconnect failed: %w", reconnectErr)
		}
		// Retry the write with new connection
		cm.mu.RLock()
		conn = cm.conn
		cm.mu.RUnlock()
		return conn.Write(data)
	}

	return n, nil
}

// Read reads data from the connection with reconnection logic
func (cm *ConnectionManager) Read(data []byte) (int, error) {
	cm.mu.RLock()
	conn := cm.conn
	cm.mu.RUnlock()

	if conn == nil {
		if err := cm.Connect(); err != nil {
			return 0, err
		}
		cm.mu.RLock()
		conn = cm.conn
		cm.mu.RUnlock()
	}

	n, err := conn.Read(data)
	if err != nil {
		utils.Log("valkey").Error("Read error: %v", err)
		// Try to reconnect on read error
		if reconnectErr := cm.Connect(); reconnectErr != nil {
			return n, fmt.Errorf("read failed and reconnect failed: %w", reconnectErr)
		}
		// Return the original error since we can't retry the read
		return n, err
	}

	return n, nil
}

// Close closes the connection
func (cm *ConnectionManager) Close() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if cm.conn != nil {
		err := cm.conn.Close()
		cm.conn = nil
		return err
	}
	return nil
}

// GetConn returns the underlying connection for operations that need it directly
func (cm *ConnectionManager) GetConn() net.Conn {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	return cm.conn
}

// Printf writes formatted data to the connection with reconnection logic
func (cm *ConnectionManager) Fprintf(format string, args ...any) (int, error) {
	data := fmt.Sprintf(format, args...)
	return cm.Write([]byte(data))
}
