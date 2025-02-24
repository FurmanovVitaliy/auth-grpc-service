CREATE TABLE IF NOT EXISTS users
(
    id          SERIAL PRIMARY KEY,
    email       VARCHAR(255) NOT NULL UNIQUE,
    username    VARCHAR(255) NOT NULL UNIQUE,
    pass_hash   BYTEA NOT NULL,
    provider    VARCHAR(50) DEFAULT 'local',
    created_at  TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    last_login  TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    avatar_url  TEXT DEFAULT '',
    role        SMALLINT DEFAULT 0,
    is_blocked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS users_email_idx ON users (email);
CREATE INDEX IF NOT EXISTS users_username_idx ON users (username);

CREATE TABLE IF NOT EXISTS apps
(
    id     SERIAL PRIMARY KEY,
    name   VARCHAR(255) NOT NULL UNIQUE,
    secret TEXT NOT NULL UNIQUE
);
