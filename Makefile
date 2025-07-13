db:
	rm -f storage/sqlite/database.db && touch storage/sqlite/database.db && sqlite3 storage/sqlite/database.db < storage/sqlite/schema.sql
	cd storage/sqlite && DB_URI="file://database.db" go run github.com/sqlc-dev/sqlc/cmd/sqlc@latest generate 
