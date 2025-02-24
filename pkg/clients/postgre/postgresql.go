package postgre

import (
	"context"
	"fmt"
	"time"

	"github.com/FurmanovVitaliy/auth-grpc-service/utils"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
)

type PostgresClient interface {
	Exec(ctx context.Context, sql string, arguments ...interface{}) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row
	Begin(ctx context.Context) (pgx.Tx, error)
	Close()
}

func NewPostgresClient(ctx context.Context, maxAttempts int, host, port, username, password, database string) (pool *pgxpool.Pool, version string, err error) {

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", username, password, host, port, database)
	err = utils.DoWithRetry(func() error {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		pool, err = pgxpool.Connect(ctx, dsn)
		if err != nil {
			return err
		}
		err = pool.Ping(ctx)
		if err != nil {
			return err
		}

		return nil
	}, maxAttempts, 5*time.Second)

	err = pool.QueryRow(context.TODO(), "SELECT version()").Scan(&version)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get Postgres version: %w", err)
	}

	if err != nil {
		return nil, "", fmt.Errorf("failed to connect to Postgres after %d attempts: %w", maxAttempts, err)
	}

	return pool, version, nil
}
