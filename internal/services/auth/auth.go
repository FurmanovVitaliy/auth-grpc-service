package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/FurmanovVitaliy/auth-grpc-service/internal/domain/models"
	"github.com/FurmanovVitaliy/auth-grpc-service/internal/storage"
	"github.com/FurmanovVitaliy/auth-grpc-service/pkg/jwt"
	"github.com/FurmanovVitaliy/logger"
)

type Auth struct {
	log             *slog.Logger
	userRegistrator UserRegirtator
	userProvider    UserProvider
	appProvider     AppProvider
	tokenTTL        time.Duration
}

type UserRegirtator interface {
	Register(ctx context.Context, email, password string) (userID int64, err error)
	Update(ctx context.Context, userID int64, email, password string) error
	Delete(ctx context.Context, userID int64) error
}

type UserProvider interface {
	User(ctx context.Context, email string) (user models.User, err error)
	IsAdmin(ctx context.Context, userID int64) (isAdmin bool, err error)
}

type AppProvider interface {
	App(ctx context.Context, appID int) (app models.App, err error)
}

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidAppId       = errors.New("invalid app id")
)

// New creates a new instance of the Auth service.
func New(
	log *slog.Logger,
	userRegistrator UserRegirtator,
	userProvider UserProvider,
	appProvider AppProvider,
	tokenTTL time.Duration,
) *Auth {
	return &Auth{
		log:             log,
		userRegistrator: userRegistrator,
		userProvider:    userProvider,
		appProvider:     appProvider,
		tokenTTL:        tokenTTL,
	}
}

// Login checks if the user with given credentials exists in system and returns a token.
//
// If the user does not exist or the password is incorrect, an error is returned.
func (a *Auth) Login(
	ctx context.Context,
	email, password string,
	appID int,
) (string, error) {
	const op = "auth.Auth.Login"
	log := a.log.With(
		slog.String("op", op),
		slog.String("email", maskEmail(email)),
	)

	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", logger.ErrAttr(err))
			return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
		}
		a.log.Error("failed to get the user", logger.ErrAttr(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PassHash), []byte(password)); err != nil {
		a.log.Warn("invalid password", logger.ErrAttr(err))
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user logged in successfully")

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to create a token", logger.ErrAttr(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil
}

// Register creates a new user with given credentials.
//
// If the user with given email already exists, an error is returned.
func (a *Auth) Register(
	ctx context.Context,
	email, password string,
) (int64, error) {
	const op = "auth.Auth.Register"
	log := a.log.With(
		slog.String("op", op),
		slog.String("email", maskEmail(email)),
	)

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to hash the password", logger.ErrAttr(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.userRegistrator.Register(ctx, email, string(passHash))
	if err != nil {
		if errors.Is(err, storage.ErrUserAlreadyExists) {
			log.Warn("user already exists", logger.ErrAttr(err))
			return 0, fmt.Errorf("%s: %w", op, ErrUserAlreadyExists)
		}
		log.Error("failed to register the user", logger.ErrAttr(err))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user registered")
	return id, err
}

// IsAdmin checks if the user with given ID is an admin.
func (a *Auth) IsAdmin(
	ctx context.Context,
	userID int64,
) (bool, error) {
	const op = "auth.Auth.IsAdmin"
	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)

	log.Info("checking if the user is an admin")

	IsAdmin, err := a.userProvider.IsAdmin(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrAppNotFound) {
			return false, fmt.Errorf("%s: %w", op, ErrInvalidAppId)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user is an admin", slog.Bool("is_admin", IsAdmin))
	return IsAdmin, nil
}

// maskEmail masks the email address by replacing some characters with asterisks.
// Example: example@example.com ->  ex*****@*******le.com
func maskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}

	localPart := parts[0]
	domainPart := parts[1]

	if len(localPart) > 2 {
		localPart = localPart[:2] + strings.Repeat("*", len(localPart)-2)
	}

	if len(domainPart) > 2 {
		domainPart = strings.Repeat("*", len(domainPart)-2) + domainPart[len(domainPart)-2:]
	}

	return localPart + "@" + domainPart
}
