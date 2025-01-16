-- name: CreateChirp :one
INSERT INTO chirps (id, created_at, updated_at, user_id, body)
VALUES (
       gen_random_uuid(),
       now(),
       now(),
       $1,
       $2
)
RETURNING *;

-- name: GetChirps :many
SELECT * FROM chirps ORDER BY created_at ASC;

-- name: GetChirpsByUser :many
SELECT * FROM chirps WHERE user_id = $1 ORDER BY created_at ASC;

-- name: DeleteChirps :exec
DELETE FROM chirps;

-- name: DeleteChirp :exec
DELETE FROM chirps WHERE id = $1;

-- name: DeleteChirpsByUser :exec
DELETE FROM chirps WHERE user_id = $1;

-- name: GetChirp :one
SELECT * FROM chirps WHERE id = $1;
