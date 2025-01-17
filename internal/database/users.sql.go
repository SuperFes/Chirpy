// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: users.sql

package database

import (
	"context"

	"github.com/google/uuid"
)

const createUser = `-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, password)
VALUES (gen_random_uuid(),
        now(),
        now(),
        $1,
        $2)
RETURNING id, created_at, updated_at, email, password, is_chirpy_red
`

type CreateUserParams struct {
	Email    string
	Password string
}

func (q *Queries) CreateUser(ctx context.Context, arg CreateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, createUser, arg.Email, arg.Password)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.Password,
		&i.IsChirpyRed,
	)
	return i, err
}

const deleteUsers = `-- name: DeleteUsers :exec
DELETE
FROM users
`

func (q *Queries) DeleteUsers(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, deleteUsers)
	return err
}

const getUser = `-- name: GetUser :one
SELECT id, created_at, updated_at, email, password, is_chirpy_red FROM users WHERE email = $1
`

func (q *Queries) GetUser(ctx context.Context, email string) (User, error) {
	row := q.db.QueryRowContext(ctx, getUser, email)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.Password,
		&i.IsChirpyRed,
	)
	return i, err
}

const getUserById = `-- name: GetUserById :one
SELECT id, created_at, updated_at, email, password, is_chirpy_red FROM users WHERE id = $1
`

func (q *Queries) GetUserById(ctx context.Context, id uuid.UUID) (User, error) {
	row := q.db.QueryRowContext(ctx, getUserById, id)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.Password,
		&i.IsChirpyRed,
	)
	return i, err
}

const updateIsRed = `-- name: UpdateIsRed :one
UPDATE users
SET is_chirpy_red = $2
WHERE id = $1
RETURNING id, created_at, updated_at, email, password, is_chirpy_red
`

type UpdateIsRedParams struct {
	ID          uuid.UUID
	IsChirpyRed bool
}

func (q *Queries) UpdateIsRed(ctx context.Context, arg UpdateIsRedParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateIsRed, arg.ID, arg.IsChirpyRed)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.Password,
		&i.IsChirpyRed,
	)
	return i, err
}

const updateUser = `-- name: UpdateUser :one
UPDATE users
SET updated_at = now(),
    email = $2,
    password = $3
WHERE id = $1
RETURNING id, created_at, updated_at, email, password, is_chirpy_red
`

type UpdateUserParams struct {
	ID       uuid.UUID
	Email    string
	Password string
}

func (q *Queries) UpdateUser(ctx context.Context, arg UpdateUserParams) (User, error) {
	row := q.db.QueryRowContext(ctx, updateUser, arg.ID, arg.Email, arg.Password)
	var i User
	err := row.Scan(
		&i.ID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.Email,
		&i.Password,
		&i.IsChirpyRed,
	)
	return i, err
}
