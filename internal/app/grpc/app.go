package grpcapp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	authgrpc "github.com/FurmanovVitaliy/auth-grpc-service/internal/grpc/auth"
	"github.com/FurmanovVitaliy/logger"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

type App struct {
	log        *slog.Logger
	gRPCServer *grpc.Server
	port       int
}

// New create a new gRPC Server
func New(
	log *slog.Logger,
	port int,
	tlsEnabled bool,
	timeout time.Duration,
	tlsCertFile string,
	tlsKeyFile string,
	authgService authgrpc.Auth,
) *App {
	var opts []grpc.ServerOption
	if tlsEnabled {
		creds, err := credentials.NewServerTLSFromFile(tlsCertFile, tlsKeyFile)
		if err != nil {
			log.Error("failed to create TLS credentials", logger.ErrAttr(err))
			panic(err)
		}
		opts = append(opts, grpc.Creds(creds))
	}
	opts = append(opts, grpc.UnaryInterceptor(timeoutInterceptor(timeout)))

	gRPCServer := grpc.NewServer(opts...)
	authgrpc.Register(gRPCServer, authgService)

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

	reflection.Register(a.gRPCServer)

	log := a.log.With(
		slog.String("op", op),
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

func timeoutInterceptor(timeout time.Duration) grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return handler(ctx, req)
	}
}
