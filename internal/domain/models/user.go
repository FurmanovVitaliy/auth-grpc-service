package models

import "time"

type User struct {
	ID        int64
	Email     string
	Username  string
	PassHash  []byte
	Provider  string
	CreatedAT time.Time
	LastLogIn *time.Time
	Avatar    string
	Role      int32
	IsBlocked bool
}
