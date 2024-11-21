package postgre

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/FurmanovVitaliy/auth-grpc-service/internal/domain/models"
	"github.com/FurmanovVitaliy/auth-grpc-service/internal/storage"
	"github.com/FurmanovVitaliy/auth-grpc-service/pkg/clents/postgre"
	"github.com/jackc/pgconn"
)

type Storage struct {
	client postgre.PostgresClient
	log    *slog.Logger
}

func formatQuery(q string) string {
	return strings.ReplaceAll(strings.ReplaceAll(q, "\t", ""), "\n", " ")
}
func (s *Storage) Register(ctx context.Context, email, password string) (int64, error) {
	const op = "storage.postgre.Register"
	var id int64

	q := `INSERT INTO users (email, pass_hash) VALUES ($1, $2) RETURNING id`

	s.log.Debug("SQL register query:", slog.String("query", formatQuery(q)))
	if err := s.client.QueryRow(ctx, q, email, password).Scan(&id); err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok {
			if pgErr.Code == "23505" {
				return 0, storage.ErrUserAlreadyExists
			}
			return 0, fmt.Errorf(fmt.Sprintf("%s: SQL Error: %s, Detail: %s, Where: %s, Code: %s, SQLState: %s", op, pgErr.Message, pgErr.Detail, pgErr.Where, pgErr.Code, pgErr.SQLState()))
		}
		return 0, fmt.Errorf("%s: %v", op, err)
	}
	return id, nil
}

func (s *Storage) User(ctx context.Context, email string) (models.User, error) {
	const op = "storage.postgre.User"
	var user models.User

	q := `SELECT id, email, pass_hash FROM users WHERE email = $1`

	s.log.Debug("SQL user query:", slog.String("query", formatQuery(q)))
	row := s.client.QueryRow(ctx, q, email)
	if err := row.Scan(&user.ID, &user.Email, &user.PassHash); err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok {
			return models.User{}, fmt.Errorf(fmt.Sprintf("%s: SQL Error: %s, Detail: %s, Where: %s, Code: %s, SQLState: %s", op, pgErr.Message, pgErr.Detail, pgErr.Where, pgErr.Code, pgErr.SQLState()))
		}
		if err.Error() == "no rows in result set" {
			return models.User{}, storage.ErrUserNotFound
		}
		return models.User{}, fmt.Errorf("%s: %v", op, err)
	}
	return user, nil
}

func (s *Storage) Update(ctx context.Context, id int64, email, password string) error {
	const op = "storage.postgre.Update"

	q := `UPDATE users SET email = $1, password = $2 WHERE id = $3`

	s.log.Debug("SQL update query:", slog.String("query", formatQuery(q)))
	if _, err := s.client.Exec(ctx, q, email, password, id); err != nil {
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

func (s *Storage) IsAdmin(ctx context.Context, id int64) (bool, error) {
	const op = "storage.postgre.IsAdmin"
	var isAdmin bool

	q := `SELECT is_admin FROM users WHERE id = $1`

	s.log.Debug("SQL is_admin query:", slog.String("query", formatQuery(q)))
	row := s.client.QueryRow(ctx, q, id)
	if err := row.Scan(&isAdmin); err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok {
			return false, fmt.Errorf(fmt.Sprintf("%s: SQL Error: %s, Detail: %s, Where: %s, Code: %s, SQLState: %s", op, pgErr.Message, pgErr.Detail, pgErr.Where, pgErr.Code, pgErr.SQLState()))
		}
		return false, fmt.Errorf("%s: %v", op, err)
	}
	return isAdmin, nil
}

func (s *Storage) App(ctx context.Context, id int) (models.App, error) {
	const op = "storage.postgre.App"
	var app models.App

	q := `SELECT id, name, secret FROM apps WHERE id = $1`

	s.log.Debug("SQL app query:", slog.String("query", formatQuery(q)))
	row := s.client.QueryRow(ctx, q, id)
	if err := row.Scan(&app.ID, &app.Name, &app.Secret); err != nil {
		if pgErr, ok := err.(*pgconn.PgError); ok {
			if pgErr.Code == "23505" {
				return app, fmt.Errorf("%s: %s", op, storage.ErrAppNotFound)
			}
			return app, fmt.Errorf(fmt.Sprintf("%s: SQL Error: %s, Detail: %s, Where: %s, Code: %s, SQLState: %s", op, pgErr.Message, pgErr.Detail, pgErr.Where, pgErr.Code, pgErr.SQLState()))
		}
		return app, fmt.Errorf("%s: %v", op, err)
	}
	return app, nil
}

func NewStorage(logger *slog.Logger, ctx context.Context, client postgre.PostgresClient) *Storage {
	return &Storage{client: client, log: logger}
}
