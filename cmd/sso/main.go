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

func main() {
	var log *slog.Logger
	ctx := context.Background()

	logger.ExtractLogger(ctx).Info("starting sso-service")
	logger.ExtractLogger(ctx).Info("loading configuration")

	cfg := config.MustLoad()

	switch cfg.Env {
	case "local":
		log = logger.NewLogger(
			logger.WithLevel(cfg.Logger.Level), logger.IsJSON(false),
			logger.WithSource(cfg.Logger.Source), logger.IsPrettyOut(true),
		)
	case "dev":
		log = logger.NewLogger(
			logger.WithLevel(cfg.Logger.Level), logger.IsJSON(cfg.Logger.JSON),
			logger.WithSource(cfg.Logger.Source),
		)
	case "prod":
		log = logger.NewLogger(
			logger.WithLevel(cfg.Logger.Level), logger.IsJSON(cfg.Logger.JSON),
			logger.WithSource(cfg.Logger.Source),
		)
	}

	log.Info("configuration loaded", "config", cfg.LogValue())

	application := app.New(
		log,
		cfg,
	)

	go func() {
		application.GRPCServer.MustRun()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	call := <-stop

	log.Info("stopping application", slog.String("signal", call.String()))
	application.GRPCServer.Stop()

	log.Info("stopping postgreSQL connection")
	application.DbConnection.Close()

	log.Info("stopping redis connection")
	application.CacheConnection.Close()

	log.Info("application stopped")
}
