package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/FurmanovVitaliy/auth-grpc-service/internal/app"
	"github.com/FurmanovVitaliy/auth-grpc-service/internal/config"
	"github.com/FurmanovVitaliy/auth-grpc-service/internal/lib/logger/handlers/slogpretty"
)

const (
	envLocal = "local"
	envDev   = "dev"
	envProd  = "prod"
)

func main() {
	cfg := config.MustLoad()

	log := setUpLogger(cfg.Env)

	log.Info("starting application")

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

func setUpLogger(env string) *slog.Logger {
	var log *slog.Logger

	switch env {
	case envLocal:
		log = setupPrettySlog()
	case envDev:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}),
		)
	case envProd:
		log = slog.New(
			slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}),
		)
	}

	return log
}

func setupPrettySlog() *slog.Logger {
	opts := slogpretty.PrettyHandlerOptions{
		SlogOpts: &slog.HandlerOptions{
			Level: slog.LevelDebug,
		},
	}

	handler := opts.NewPrettyHandler(os.Stdout)

	return slog.New(handler)
}
