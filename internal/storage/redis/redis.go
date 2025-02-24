// internal/storage/redis/redis.go
package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/FurmanovVitaliy/auth-grpc-service/internal/domain/models"
	"github.com/FurmanovVitaliy/auth-grpc-service/pkg/clients/redis"
	"github.com/FurmanovVitaliy/logger"
)

type Storage struct {
	client redis.RedisClient
	log    *slog.Logger
}

func genRedisKeyPattern(params models.SessionKey) string {
	parts := []string{"server_session"}

	if params.AppID != 0 {
		parts = append(parts, fmt.Sprintf("app_id:%d", params.AppID))
	} else {
		parts = append(parts, "app_id:*")
	}

	if params.UserID != 0 {
		parts = append(parts, fmt.Sprintf("user_id:%d", params.UserID))
	} else {
		parts = append(parts, "user_id:*")
	}

	if params.SessionID != "" {
		parts = append(parts, fmt.Sprintf("session_id:%s", params.SessionID))
	} else {
		parts = append(parts, "session_id:*")
	}

	return strings.Join(parts, ":")
}

func NewStorage(logger *slog.Logger, client redis.RedisClient) *Storage {
	return &Storage{client: client, log: logger}
}

func (s *Storage) Create(ctx context.Context, key models.SessionKey, appName, userIP, userAgent, refreshHash, refreshSecret string, exp time.Time) error {
	const op = "redis.Storage.Create"
	log := s.log.With(
		logger.StringAttr("operation", op),
	)

	now := time.Now().UTC()
	session := models.Session{
		ID:            key.SessionID,
		UserID:        key.UserID,
		AppID:         key.AppID,
		AppName:       appName,
		RefreshToken:  refreshHash,
		RefreshSecret: refreshSecret,
		Status:        0,
		UserAgent:     userAgent,
		IPAddress:     userIP,
		CreatedAt:     now,
		UpdatedAt:     &now,
	}

	data, err := json.Marshal(session)
	if err != nil {
		log.Error("failed to marshal session", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}
	if err := s.client.Set(ctx, genRedisKeyPattern(key), string(data), time.Until(exp)); err != nil {
		log.Error("failed to set session", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (s *Storage) GetByID(ctx context.Context, key models.SessionKey) (models.Session, error) {
	const op = "redis.Storage.GetByID"
	log := s.log.With(
		logger.StringAttr("operation", op),
	)
	if key.AppID == 0 {
		log.Error("No session ID")
		return models.Session{}, fmt.Errorf("Session id mus be exist ")
	}
	sessions, err := s.getSessions(ctx, key)
	if err != nil {
		return models.Session{}, err
	}
	if len(sessions) > 1 {
		log.Warn("multiple sessions found, using the first one")
	}
	return sessions[0], nil
}
func (s *Storage) GetByParam(ctx context.Context, key models.SessionKey) ([]models.Session, error) {
	return s.getSessions(ctx, key)
}

func (s *Storage) getSessions(ctx context.Context, key models.SessionKey) ([]models.Session, error) {
	const op = "redis.Storage.getSessions"
	log := s.log.With(
		logger.StringAttr("operation", op),
	)

	pattern := genRedisKeyPattern(key)
	keys, err := s.client.Keys(ctx, pattern)
	if err != nil {
		log.Error("failed to search session key", logger.ErrAttr(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}
	if len(keys) == 0 {
		log.Warn("session not found")
		return nil, fmt.Errorf("%s: session not found", op)
	}
	var sessions []models.Session
	for _, key := range keys {
		data, err := s.client.Get(ctx, key)
		if err != nil {
			log.Warn("failed to get session", logger.ErrAttr(err))
			continue
		}

		var session models.Session
		if err := json.Unmarshal([]byte(data), &session); err != nil {
			log.Error("failed to unmarshal session", logger.ErrAttr(err))
			return nil, fmt.Errorf("%s: %w", op, err)
		}
		sessions = append(sessions, session)
	}
	return sessions, nil

}

func (s *Storage) Revoke(ctx context.Context, sessionID string) error {
	const op = "redis.Storage.Revoke"
	log := s.log.With(
		logger.StringAttr("operation", op),
		logger.StringAttr("session_id", sessionID),
	)

	pattern := fmt.Sprintf("server_session:app_id:*:user_id:*:session_id:%s", sessionID)
	keys, err := s.client.Keys(ctx, pattern)
	if err != nil {
		log.Error("failed to search session key", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}
	if len(keys) == 0 {
		log.Warn("session not found")
		return fmt.Errorf("%s: session not found", op)
	}
	if len(keys) > 1 {
		log.Warn("multiple sessions found")
		//TODO: обработать ситуацию, когда найдено несколько сессий
	}

	key := keys[0]

	data, err := s.client.Get(ctx, key)
	if err != nil {
		log.Error("failed to get session data", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	var session models.Session
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		log.Error("failed to unmarshal session data", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}
	session.Status = 2
	now := time.Now().UTC()
	session.UpdatedAt = &now

	updatedData, err := json.Marshal(session)
	if err != nil {
		log.Error("failed to marshal updated session", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	ttl, err := s.client.TTL(ctx, key)
	if err != nil {
		log.Error("failed to get session TTL", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	if err := s.client.Set(ctx, key, string(updatedData), ttl); err != nil {
		log.Error("failed to update session in Redis", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("session successfully revoked")
	return nil
}

// Сохранение OAuth-сессии
func (s *Storage) SaveOAuthSession(ctx context.Context, appID int32, provider, session, state string) error {
	const op = "redis.Storage.SaveOAuthSession"
	log := s.log.With(
		logger.StringAttr("operation", op),
		logger.Int32Attr("app_id", appID),
		logger.StringAttr("provider", provider),
		logger.StringAttr("session", session),
		logger.StringAttr("state", state),
	)

	key := fmt.Sprintf("oauth_session:%s:%s", provider, state)

	oauthSession := models.OAuthSession{
		Session: session,
		AppID:   appID,
		Status:  0,
	}
	data, err := json.Marshal(oauthSession)
	if err != nil {
		log.Error("failed to marshal OAuth session", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	err = s.client.Set(ctx, key, data, 5*time.Minute)
	if err != nil {
		log.Error("failed to save OAuth session", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("OAuth session successfully saved", logger.StringAttr("key", key))
	return nil
}

func (s *Storage) GetOAuthSession(ctx context.Context, provider, state string) (models.OAuthSession, error) {
	const op = "redis.Storage.GetOAuthSession"
	log := s.log.With(
		logger.StringAttr("operation", op),
		logger.StringAttr("provider", provider),
		logger.StringAttr("state", state),
	)

	key := fmt.Sprintf("oauth_session:%s:%s", provider, state)

	value, err := s.client.Get(ctx, key)
	if err != nil {
		log.Error("failed to get OAuth session", logger.ErrAttr(err))
		return models.OAuthSession{}, err
	}

	var oauthSession models.OAuthSession

	err = json.Unmarshal([]byte(value), &oauthSession)
	if err != nil {
		log.Error("failed to unmarshal OAuth session", logger.ErrAttr(err))
		return models.OAuthSession{}, fmt.Errorf("%s: %w", op, err)
	}

	originalStatus := oauthSession.Status

	if originalStatus == 1 {
		log.Info("OAuth session already has status 1, no update necessary", logger.StringAttr("key", key))
		return oauthSession, nil
	}

	oauthSession.Status = 1

	updatedData, err := json.Marshal(oauthSession)
	if err != nil {
		log.Error("failed to marshal updated OAuth session", logger.ErrAttr(err))
		return models.OAuthSession{}, fmt.Errorf("%s: %w", op, err)
	}

	ttl, err := s.client.TTL(ctx, key)
	if err != nil {
		log.Error("failed to get session TTL", logger.ErrAttr(err))
		return models.OAuthSession{}, fmt.Errorf("%s: %w", op, err)
	}

	if err := s.client.Set(ctx, key, string(updatedData), ttl); err != nil {
		log.Error("failed to update session in Redis", logger.ErrAttr(err))
		return models.OAuthSession{}, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("OAuth session successfully updated in Redis", logger.StringAttr("key", key))

	oauthSession.Status = originalStatus
	return oauthSession, nil
}
