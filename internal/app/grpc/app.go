package grpcapp

import (
	"fmt"
	"log/slog"
	"net"

	authgrpc "github.com/FurmanovVitaliy/auth-grpc-service/internal/grpc/auth"

	"google.golang.org/grpc"
)

type App struct {
	log        *slog.Logger
	gRPCServer *grpc.Server
	port       int
}

// New create a new gRPC Server
func New(
	log *slog.Logger,
	authgSetvice authgrpc.Auth,
	port int,
) *App {
	gRPCServer := grpc.NewServer()
	authgrpc.Register(gRPCServer, authgSetvice)

	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
	}
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

func (a *App) Run() error {
	const op = "grpcapp.App.Run"

	log := a.log.With(
		slog.String("op", op),
		slog.Int("port", a.port),
	)
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	log.Info("grpc server is running", slog.String("addr", l.Addr().String()))
	if err := a.gRPCServer.Serve(l); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (a *App) Stop() {

	const op = "grpcapp.App.Stop"
	a.log.With(slog.String("op", op)).
		Info("stoping gRPC server", slog.Int("port", a.port))

	a.gRPCServer.GracefulStop()
}
