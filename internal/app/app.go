package app

import (
	"context"
	"log/slog"

	grpcapp "github.com/FurmanovVitaliy/auth-grpc-service/internal/app/grpc"
	"github.com/FurmanovVitaliy/auth-grpc-service/internal/config"
	"github.com/FurmanovVitaliy/auth-grpc-service/internal/services/auth"
	"github.com/FurmanovVitaliy/auth-grpc-service/internal/storage/postgre"
	"github.com/FurmanovVitaliy/auth-grpc-service/internal/storage/redis"
	pgClient "github.com/FurmanovVitaliy/auth-grpc-service/pkg/clients/postgre"
	redisClient "github.com/FurmanovVitaliy/auth-grpc-service/pkg/clients/redis"
	"github.com/markbates/goth"
	"github.com/markbates/goth/providers/github"
)

type App struct {
	GRPCServer      *grpcapp.App
	DbConnection    pgClient.PostgresClient
	CacheConnection redisClient.RedisClient
}

func New(
	log *slog.Logger,
	cfg *config.Config,
) *App {

	postgreSQlClient, version, err := pgClient.NewPostgresClient(context.Background(), 5, cfg.Postgres.Host, cfg.Postgres.Port, cfg.Postgres.Username, cfg.Postgres.Password, cfg.Postgres.Database)
	if err != nil {
		panic(err)
	}
	log.Info("postreSQL connected", slog.String("version", version))

	redisCacheClient, version, err := redisClient.NewRedisClient(context.Background(), 5, cfg.Redis.Host, cfg.Redis.Port, cfg.Redis.Password, cfg.Redis.Database)
	if err != nil {
		panic(err)
	}

	log.Info("redis connected", slog.String("version", version))

	dbStorage := postgre.NewStorage(log, postgreSQlClient)
	cacheStorage := redis.NewStorage(log, redisCacheClient)

	//cacheStorage := redis.NewStorag
	authService := auth.New(log, dbStorage, dbStorage, cacheStorage, cfg.AccessTokenTTL, cfg.RefreshTokenTTL)
	grpcApp := grpcapp.New(log, cfg.GRPC.Port, cfg.GRPC.TLSEnabled, cfg.GRPC.Timeout, cfg.Cert.Cert, cfg.Cert.Key, authService)

	//init providers
	goth.UseProviders(
		github.New(cfg.Providers.GithubPrivider.ID, cfg.Providers.GithubPrivider.Secret, cfg.Providers.GithubPrivider.Callback),
	)

	return &App{
		GRPCServer:   grpcApp,
		DbConnection: postgreSQlClient,
	}
}
