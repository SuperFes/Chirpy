-- +goose Up
CREATE TABLE chirps
(
    id         UUID      NOT NULL PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    updated_at TIMESTAMP NOT NULL,
    user_id    UUID      NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    body       TEXT      NOT NULL
);

-- +goose Down
DROP TABLE chirps;
