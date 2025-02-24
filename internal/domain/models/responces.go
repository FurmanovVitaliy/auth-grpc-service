package models

import "time"

type LoginResponse struct {
	SessionID             string
	AccessToken           string
	AccessTokenExpiresAt  time.Time
	RefreshToken          string
	RefreshTokenExpiresAt time.Time
}

type RefreshTokenResponse struct {
	AccessToken          string
	AccessTokenExpiresAt time.Time
}

type SessionResponce struct {
	SessionID    string
	UserIP       string
	UserAgent    string
	UserDevice   string
	AppName      string
	Status       int32
	CreatedAt    time.Time
	LastActivity time.Time
}
