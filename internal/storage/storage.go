package storage

import "errors"

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrAppNotFound       = errors.New("app not found")
	ErrUserAlreadyExists = errors.New("user already exists")
)
