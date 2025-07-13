package sqlite

import (
	"os"
	"testing"

	"github.com/nathan-hello/nat-auth/storage"
)

func TestSQLiteDbPasswordInterface(t *testing.T) {
	// Test that SQLiteDB implements DbPassword interface
	var _ storage.DbPassword = (*SQLiteDB)(nil)

	// Create a temporary database file
	tempDB := "./test_temp.db"
	defer os.Remove(tempDB)

	// Create database and apply schema
	os.Remove(tempDB)                     // Ensure it doesn't exist
	err := os.Rename("./test.db", tempDB) // Use the existing test.db with schema
	if err != nil {
		t.Fatalf("Failed to setup test database: %v", err)
	}

	// Initialize the database
	db, err := NewSQLiteDB(tempDB)
	if err != nil {
		t.Fatalf("Failed to create SQLite database: %v", err)
	}
	defer db.Close()

	// Test basic operations
	username := "testuser"
	password := "testpass"

	// Test user insertion
	err = db.InsertUser(username, password)
	if err != nil {
		t.Errorf("Failed to insert user: %v", err)
	}

	// Test password retrieval
	retrievedPass, err := db.SelectPasswordByUsername(username)
	if err != nil {
		t.Errorf("Failed to select password: %v", err)
	}
	if retrievedPass != password {
		t.Errorf("Expected password %s, got %s", password, retrievedPass)
	}

	// Test subject operations
	subject := "test-subject-123"
	err = db.InsertSubject(username, subject)
	if err != nil {
		t.Errorf("Failed to insert subject: %v", err)
	}

	retrievedSubject, err := db.SelectSubjectByUsername(username)
	if err != nil {
		t.Errorf("Failed to select subject: %v", err)
	}
	if retrievedSubject != subject {
		t.Errorf("Expected subject %s, got %s", subject, retrievedSubject)
	}

	// Test TOTP secret operations
	secret := "test-secret-456"
	err = db.InsertSecret(subject, secret)
	if err != nil {
		t.Errorf("Failed to insert secret: %v", err)
	}

	retrievedSecret, err := db.SelectSecret(subject)
	if err != nil {
		t.Errorf("Failed to select secret: %v", err)
	}
	if retrievedSecret != secret {
		t.Errorf("Expected secret %s, got %s", secret, retrievedSecret)
	}

	// Test JWT family operations
	family := "test-family"
	err = db.InsertFamily(subject, family, true)
	if err != nil {
		t.Errorf("Failed to insert family: %v", err)
	}

	isValid := db.SelectFamily(subject, family)
	if !isValid {
		t.Errorf("Expected family to be valid")
	}

	// Test user invalidation
	err = db.InvalidateUser(subject)
	if err != nil {
		t.Errorf("Failed to invalidate user: %v", err)
	}

	isValid = db.SelectFamily(subject, family)
	if isValid {
		t.Errorf("Expected family to be invalid after user invalidation")
	}

	// Test UUID generation
	uuid, err := db.NewUserId()
	if err != nil {
		t.Errorf("Failed to generate UUID: %v", err)
	}
	if len(uuid) != 36 {
		t.Errorf("Expected UUID length 36, got %d", len(uuid))
	}
}
