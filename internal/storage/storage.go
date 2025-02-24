package storage

import "errors"

var (
	ErrUserNotFound         = errors.New("user not found")
	ErrAppNotFound          = errors.New("app not found")
	ErrEmailAlreadyExists   = errors.New("user already exists")
	ErrUsenameAlreadyExists = errors.New("username already exists")
)

var (
	ErrSessionAlreadyExists = errors.New("session already exists")
	ErrSessionNotFound      = errors.New("session not found")
	ErrInvalidSessionFormat = errors.New("invalid session format")
)
