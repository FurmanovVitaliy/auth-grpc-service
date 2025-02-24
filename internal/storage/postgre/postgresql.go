package postgre

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/FurmanovVitaliy/auth-grpc-service/internal/domain/models"
	"github.com/FurmanovVitaliy/auth-grpc-service/internal/storage"
	"github.com/FurmanovVitaliy/auth-grpc-service/pkg/clients/postgre"
	"github.com/FurmanovVitaliy/auth-grpc-service/utils"
	"github.com/FurmanovVitaliy/logger"
	"github.com/jackc/pgconn"
)

type Storage struct {
	client postgre.PostgresClient
	log    *slog.Logger
}

func formatQuery(q string) string {
	return strings.ReplaceAll(strings.ReplaceAll(q, "\t", ""), "\n", " ")
}
func (s *Storage) Register(ctx context.Context, email, username, passHash, avatarURL, provider string) (err error) {
	const op = "storage.postgre.Register"
	var id int64

	q := `INSERT INTO users (email, username, pass_hash,avatar_url,provider ) VALUES ($1, $2, $3, $4, $5 ) RETURNING id`
	s.log.Debug("SQL register query:", slog.String("query", formatQuery(q)))
	if err := s.client.QueryRow(ctx, q, email, username, passHash, avatarURL, provider).Scan(&id); err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok {
			if pgErr.Code == "23505" {
				if strings.Contains(pgErr.Message, "username") {
					return storage.ErrUsenameAlreadyExists
				}
				return storage.ErrEmailAlreadyExists
			}
			return fmt.Errorf(
				"%s: SQL Error: %s, Detail: %s, Where: %s, Code: %s, SQLState: %s",
				op, pgErr.Message, pgErr.Detail, pgErr.Where, pgErr.Code, pgErr.SQLState(),
			)
		}
		return fmt.Errorf("%s: %v", op, err)
	}
	return nil
}

func (s *Storage) UserByEmail(ctx context.Context, email string) (models.User, error) {
	const op = "storage.postgre.UserByEmail"
	log := s.log.With(slog.String("operation", op), slog.String("email", utils.MaskEmail(email)))
	var user models.User
	q := `SELECT id, email, username, pass_hash, provider, avatar_url, role, is_blocked FROM users WHERE email = $1`

	log.Debug("SQL user query:", slog.String("query", formatQuery(q)))
	row := s.client.QueryRow(ctx, q, email)
	if err := row.Scan(&user.ID, &user.Email, &user.Username, &user.PassHash, &user.Provider, &user.Avatar, &user.Role, &user.IsBlocked); err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok {
			return models.User{}, fmt.Errorf("%s: SQL Error: %s, Detail: %s, Where: %s, Code: %s, SQLState: %s", op, pgErr.Message, pgErr.Detail, pgErr.Where, pgErr.Code, pgErr.SQLState())
		}
		if err.Error() == "no rows in result set" {
			return models.User{}, storage.ErrUserNotFound
		}
		return models.User{}, fmt.Errorf("%s: %v", op, err)
	}

	time := time.Now().UTC()
	q = `UPDATE users SET last_login = $1 WHERE id = $2`
	s.log.Debug("SQL update last_login query:", slog.String("query", formatQuery(q)))
	if _, err := s.client.Exec(ctx, q, time, user.ID); err != nil {
		s.log.Warn("Failed to update last login time", logger.ErrAttr(err))
	}
	return user, nil
}

func (s *Storage) UserByID(ctx context.Context, id int64) (models.User, error) {
	const op = "storage.postgre.UserByID"
	log := s.log.With(slog.String("operation", op), slog.Int64("id", id))
	var user models.User
	q := `SELECT id, email, username, pass_hash, provider, avatar_url, role, is_blocked FROM users WHERE id = $1`

	log.Debug("SQL user query:", slog.String("query", formatQuery(q)))
	row := s.client.QueryRow(ctx, q, id)
	if err := row.Scan(&user.ID, &user.Email, &user.Username, &user.PassHash, &user.Provider, &user.Avatar, &user.Role, &user.IsBlocked); err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok {
			return models.User{}, fmt.Errorf("%s: SQL Error: %s, Detail: %s, Where: %s, Code: %s, SQLState: %s", op, pgErr.Message, pgErr.Detail, pgErr.Where, pgErr.Code, pgErr.SQLState())
		}
		if err.Error() == "no rows in result set" {
			return models.User{}, storage.ErrUserNotFound
		}
		return models.User{}, fmt.Errorf("%s: %v", op, err)
	}

	time := time.Now().UTC()
	q = `UPDATE users SET last_login = $1 WHERE id = $2`
	s.log.Debug("SQL update last_login query:", slog.String("query", formatQuery(q)))
	if _, err := s.client.Exec(ctx, q, time, user.ID); err != nil {
		s.log.Warn("Failed to update last login time", logger.ErrAttr(err))
	}
	return user, nil
}

func (s *Storage) Update(ctx context.Context, userID int64, email, username, passHash, avatarURL *string, isBlocked *bool) error {
	const op = "storage.postgre.UpdateUser"

	// Карта полей для обновления
	updates := map[string]interface{}{}
	if email != nil {
		updates["email"] = *email
	}
	if username != nil {
		updates["username"] = *username
	}
	if passHash != nil {
		updates["pass_hash"] = *passHash
	}
	if avatarURL != nil {
		updates["avatar_url"] = *avatarURL
	}
	if isBlocked != nil {
		updates["is_blocked"] = *isBlocked
	}

	// Если нет изменений, выходим
	if len(updates) == 0 {
		return nil
	}

	// Динамическая генерация SQL-запроса
	setClauses := []string{}
	args := []interface{}{}
	argID := 1

	for field, value := range updates {
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", field, argID))
		args = append(args, value)
		argID++
	}

	query := fmt.Sprintf("UPDATE users SET %s WHERE id = $%d", strings.Join(setClauses, ", "), argID)
	args = append(args, userID)

	s.log.Debug("SQL update query:", slog.String("query", formatQuery(query)))

	// Выполняем запрос
	_, err := s.client.Exec(ctx, query, args...)
	if err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok {
			if pgErr.Code == "23505" {
				if strings.Contains(pgErr.Message, "username") {
					return storage.ErrUsenameAlreadyExists
				}
				return storage.ErrEmailAlreadyExists
			}
			return fmt.Errorf(
				"%s: SQL Error: %s, Detail: %s, Where: %s, Code: %s, SQLState: %s",
				op, pgErr.Message, pgErr.Detail, pgErr.Where, pgErr.Code, pgErr.SQLState(),
			)
		}
		return fmt.Errorf("%s: %v", op, err)
	}
	return nil
}

func (s *Storage) Delete(ctx context.Context, id int64) error {
	const op = "storage.postgre.Delete"
	q := `DELETE FROM users WHERE id = $1`
	s.log.Debug("SQL delete query:", slog.String("query", formatQuery(q)))
	if _, err := s.client.Exec(ctx, q, id); err != nil {
		return fmt.Errorf("%s: %v", op, err)
	}
	return nil
}

func (s *Storage) App(ctx context.Context, id int32) (models.App, error) {
	const op = "storage.postgre.App"
	var app models.App

	q := `SELECT id, name, secret FROM apps WHERE id = $1`

	s.log.Debug("SQL app query:", slog.String("query", formatQuery(q)))
	row := s.client.QueryRow(ctx, q, id)
	if err := row.Scan(&app.ID, &app.Name, &app.Secret); err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok {
			if pgErr.Code == "23505" {
				return models.App{}, fmt.Errorf("%s: %s", op, storage.ErrAppNotFound)
			}
			return models.App{}, fmt.Errorf("%s: SQL Error: %s, Detail: %s, Where: %s, Code: %s, SQLState: %s", op, pgErr.Message, pgErr.Detail, pgErr.Where, pgErr.Code, pgErr.SQLState())
		}
		return models.App{}, fmt.Errorf("%s: %v", op, err)
	}
	return app, nil
}

func NewStorage(logger *slog.Logger, client postgre.PostgresClient) *Storage {
	return &Storage{client: client, log: logger}
}
