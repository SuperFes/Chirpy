-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, password)
VALUES (gen_random_uuid(),
        now(),
        now(),
        $1,
        $2)
RETURNING *;

-- name: DeleteUsers :exec
DELETE
FROM users;

-- name: GetUser :one
SELECT * FROM users WHERE email = $1;

-- name: GetUserById :one
SELECT * FROM users WHERE id = $1;

-- name: UpdateUser :one
UPDATE users
SET updated_at = now(),
    email = $2,
    password = $3
WHERE id = $1
RETURNING *;

-- name: UpdateIsRed :one
UPDATE users
SET is_chirpy_red = $2
WHERE id = $1
RETURNING *;
