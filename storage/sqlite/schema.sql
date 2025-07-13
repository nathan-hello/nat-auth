-- Users table to store username and password
CREATE TABLE users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL
);

-- Subjects table to map username to subject (user id)  
CREATE TABLE subjects (
    username TEXT PRIMARY KEY,
    subject TEXT NOT NULL UNIQUE,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

-- Secrets table to store TOTP secrets by subject
CREATE TABLE secrets (
    subject TEXT PRIMARY KEY,
    secret TEXT NOT NULL,
    FOREIGN KEY (subject) REFERENCES subjects(subject) ON DELETE CASCADE
);

-- Families table to store JWT family validity by subject and family
CREATE TABLE families (
    subject TEXT NOT NULL,
    family TEXT NOT NULL,
    valid BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (subject, family),
    FOREIGN KEY (subject) REFERENCES subjects(subject) ON DELETE CASCADE
); 