package models

import "time"

type Session struct {
	ID            string     `json:"id"`
	UserID        int64      `json:"uid"`
	AppID         int32      `json:"aid"`
	AppName       string     `json:"app_name"`
	IPAddress     string     `json:"ip_address"`
	UserAgent     string     `json:"user_agent"`
	RefreshToken  string     `json:"refresh_token"`
	RefreshSecret string     `json:"refresh_secret"`
	Status        int32      `json:"status"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     *time.Time `json:"updated_at"`
}

type OAuthSession struct {
	Session string `json:"session"`
	AppID   int32  `json:"app_id"`
	Status  int32  `json:"status"`
}

type SessionKey struct {
	AppID     int32
	UserID    int64
	SessionID string
}
