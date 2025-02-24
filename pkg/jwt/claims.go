package jwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type UserClaims struct {
	UID  int64 `json:"uid"`
	AID  int32 `json:"aid"`
	Role int32 `json:"role"`
	jwt.RegisteredClaims
}

type RefreshTokenClaims struct {
	UID int64  `json:"uid"`
	AID int32  `json:"aid"`
	SID string `json:"sid"`
	jwt.RegisteredClaims
}

func NewUserClaims(uid int64, aid int32, email string, role int32, duration time.Duration) (*UserClaims, error) {
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("error generating token ID: %w", err)
	}

	return &UserClaims{
		UID:  uid,
		AID:  aid,
		Role: role,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID.String(),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
		},
	}, nil
}

func NewRefreshTokenClaims(uid int64, aid int32, sid string, duration time.Duration) (*RefreshTokenClaims, error) {
	tokenID, err := uuid.NewRandom()
	if err != nil {
		return nil, fmt.Errorf("error generating token ID: %w", err)
	}
	return &RefreshTokenClaims{
		UID: uid,
		AID: aid,
		SID: sid,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        tokenID.String(),
			Subject:   sid,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
		},
	}, nil
}
