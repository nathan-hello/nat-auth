package db

import "github.com/nathan-hello/nat-auth/db/sqlite"

// In the future, this could wrap around other databases.
// The interface given by sqlc is the minimum implementation,
// so it's likely that one will stick.
type Accessor = sqlite.Querier
