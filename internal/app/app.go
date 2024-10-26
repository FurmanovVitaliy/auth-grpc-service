package app

import (
	"context"
	"log/slog"
	"time"

	grpcapp "github.com/FurmanovVitaliy/auth-grpc-service/internal/app/grpc"
	"github.com/FurmanovVitaliy/auth-grpc-service/internal/services/auth"
	"github.com/FurmanovVitaliy/auth-grpc-service/internal/storage/postgre"
	pgClient "github.com/FurmanovVitaliy/auth-grpc-service/pkg/clent/postgre"
)

type App struct {
	GRPCServer   *grpcapp.App
	DbConnection pgClient.PostgresClient
}

func New(
	log *slog.Logger,
	tokenTTL time.Duration,
	grpcPort int,
	dbHost string,
	dbPort string,
	dbUser string,
	dbPassword string,
	dbName string,

) *App {
	postgreSQlClient, version, err := pgClient.NewPostgresClient(context.Background(), 5, dbHost, dbPort, dbUser, dbPassword, dbName)
	if err != nil {
		panic(err)
	}
	log.Info("postreSQL connected", slog.String("version", version))

	storage := postgre.NewStorage(log, context.Background(), postgreSQlClient)
	authService := auth.New(log, storage, storage, storage, tokenTTL)
	grpcApp := grpcapp.New(log, authService, grpcPort)

	return &App{
		GRPCServer:   grpcApp,
		DbConnection: postgreSQlClient,
	}
}
