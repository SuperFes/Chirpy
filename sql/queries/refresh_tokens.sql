-- name: AddToken :one
INSERT INTO refresh_tokens (token, user_id, created_at, updated_at, expires_at)
VALUES ($1,
        $2,
        now(),
        now(),
        now() + interval '60 day')
RETURNING *;

-- name: RevokeToken :exec
UPDATE refresh_tokens
SET revoked_at = now(), updated_at = now()
WHERE token = $1;

-- name: GetToken :one
SELECT * FROM refresh_tokens WHERE token = $1 AND revoked_at IS NULL;

-- name: GetUserToken :one
SELECT * FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL;

-- name: RevokeTokens :exec
UPDATE refresh_tokens
SET revoked_at = now(), updated_at = now()
WHERE expires_at < now() AND revoked_at IS NULL;

-- name: RevokedTokens :many
SELECT * FROM refresh_tokens WHERE revoked_at IS NOT NULL;

-- name: GetUserFromToken :one
SELECT user_id FROM refresh_tokens WHERE token = $1 AND revoked_at IS NULL;
