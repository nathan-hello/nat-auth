CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY NOT NULL,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE NOT NULL,
    password_salt TEXT NOT NULL,
    encrypted_password TEXT NOT NULL,
    password_created_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    jwt_type TEXT NOT NULL,
    jwt TEXT NOT NULL,
    valid BOOLEAN NOT NULL,
    family TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users_tokens (
    user_id TEXT NOT NULL,
    token_id INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (token_id) REFERENCES tokens(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, token_id)
);
