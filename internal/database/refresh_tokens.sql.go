// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.27.0
// source: refresh_tokens.sql

package database

import (
	"context"

	"github.com/google/uuid"
)

const addToken = `-- name: AddToken :one
INSERT INTO refresh_tokens (token, user_id, created_at, updated_at, expires_at)
VALUES ($1,
        $2,
        now(),
        now(),
        now() + interval '60 day')
RETURNING token, user_id, created_at, updated_at, expires_at, revoked_at
`

type AddTokenParams struct {
	Token  string
	UserID uuid.UUID
}

func (q *Queries) AddToken(ctx context.Context, arg AddTokenParams) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, addToken, arg.Token, arg.UserID)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.UserID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}

const getToken = `-- name: GetToken :one
SELECT token, user_id, created_at, updated_at, expires_at, revoked_at FROM refresh_tokens WHERE token = $1 AND revoked_at IS NULL
`

func (q *Queries) GetToken(ctx context.Context, token string) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, getToken, token)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.UserID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}

const getUserFromToken = `-- name: GetUserFromToken :one
SELECT user_id FROM refresh_tokens WHERE token = $1 AND revoked_at IS NULL
`

func (q *Queries) GetUserFromToken(ctx context.Context, token string) (uuid.UUID, error) {
	row := q.db.QueryRowContext(ctx, getUserFromToken, token)
	var user_id uuid.UUID
	err := row.Scan(&user_id)
	return user_id, err
}

const getUserToken = `-- name: GetUserToken :one
SELECT token, user_id, created_at, updated_at, expires_at, revoked_at FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL
`

func (q *Queries) GetUserToken(ctx context.Context, userID uuid.UUID) (RefreshToken, error) {
	row := q.db.QueryRowContext(ctx, getUserToken, userID)
	var i RefreshToken
	err := row.Scan(
		&i.Token,
		&i.UserID,
		&i.CreatedAt,
		&i.UpdatedAt,
		&i.ExpiresAt,
		&i.RevokedAt,
	)
	return i, err
}

const revokeToken = `-- name: RevokeToken :exec
UPDATE refresh_tokens
SET revoked_at = now(), updated_at = now()
WHERE token = $1
`

func (q *Queries) RevokeToken(ctx context.Context, token string) error {
	_, err := q.db.ExecContext(ctx, revokeToken, token)
	return err
}

const revokeTokens = `-- name: RevokeTokens :exec
UPDATE refresh_tokens
SET revoked_at = now(), updated_at = now()
WHERE expires_at < now() AND revoked_at IS NULL
`

func (q *Queries) RevokeTokens(ctx context.Context) error {
	_, err := q.db.ExecContext(ctx, revokeTokens)
	return err
}

const revokedTokens = `-- name: RevokedTokens :many
SELECT token, user_id, created_at, updated_at, expires_at, revoked_at FROM refresh_tokens WHERE revoked_at IS NOT NULL
`

func (q *Queries) RevokedTokens(ctx context.Context) ([]RefreshToken, error) {
	rows, err := q.db.QueryContext(ctx, revokedTokens)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []RefreshToken
	for rows.Next() {
		var i RefreshToken
		if err := rows.Scan(
			&i.Token,
			&i.UserID,
			&i.CreatedAt,
			&i.UpdatedAt,
			&i.ExpiresAt,
			&i.RevokedAt,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}