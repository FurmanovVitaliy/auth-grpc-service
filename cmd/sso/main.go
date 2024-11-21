package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/FurmanovVitaliy/auth-grpc-service/internal/app"
	"github.com/FurmanovVitaliy/auth-grpc-service/internal/config"
	"github.com/FurmanovVitaliy/logger"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {
	var log *slog.Logger

	ctx := context.Background()
	logger.ExtractLogger(ctx).Info("starting sso-service")
	logger.ExtractLogger(ctx).Info("loading configuration")
	cfg := config.MustLoad()

	//Set up logger
	switch cfg.Env {
	case envLocal:
		log = logger.NewLogger(
			logger.WithLevel(cfg.Logger.Level), logger.IsJSON(false),
			logger.WithSource(cfg.Logger.Source), logger.IsPrettyOut(true),
		)
	case envDev:
		log = logger.NewLogger(
			logger.WithLevel(cfg.Logger.Level), logger.IsJSON(cfg.Logger.JSON),
			logger.WithSource(cfg.Logger.Source),
		)
	case envProd:
		log = logger.NewLogger(
			logger.WithLevel(cfg.Logger.Level), logger.IsJSON(cfg.Logger.JSON),
			logger.WithSource(cfg.Logger.Source),
		)
	}

	application := app.New(
		log,
		cfg.TokenTTL,
		cfg.GRPC.Port,
		cfg.Postgres.Host,
		cfg.Postgres.Port,
		cfg.Postgres.Username,
		cfg.Postgres.Password,
		cfg.Postgres.Database)

	go func() {
		application.GRPCServer.MustRun()
	}()

	//Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	call := <-stop
	log.Info("stopping application", slog.String("signal", call.String()))
	application.GRPCServer.Stop()
	log.Info("stopping postgreSQL connection")
	application.DbConnection.Close()
	log.Info("application stopped")
}
