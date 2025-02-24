// AuthService provides authentication-related services such as user registration, login, logout, token refresh,
// OAuth authentication, session management, and user blocking.
//
// The AuthService struct contains the following fields:
// - log: Logger for logging purposes.
// - userProvider: Interface for user-related operations.
// - appProvider: Interface for application-related operations.
// - sessionProvider: Interface for session-related operations.
// - accessTokenTTL: Time-to-live duration for access tokens.
// - refreshTokenTTL: Time-to-live duration for refresh tokens.
//
// The AuthService struct provides the following methods:
// - New: Creates a new instance of the AuthService.
// - Register: Registers a new user with the provided email, username, and password.
// - Login: Authenticates a user with the provided email, password, appID, userIP, and userAgent, and returns the user and login response.
// - Logout: Logs out a user by revoking the session associated with the provided sessionID.
// - RefreshToken: Refreshes the access token using the provided refresh token, IP, and agent, and returns the new access token.
// - OAuth: Initiates OAuth authentication with the specified provider and appID, and returns the authentication URL.
// - OAuthCallback: Handles the OAuth callback, completes the authentication process, and returns the user and login response.
// - Sessions: Retrieves the active sessions for the user associated with the provided access token and appID.
// - RevokeSession: Revokes a specific session for the user associated with the provided access token, appID, and sessionID.
// - RevokeAppSession: Revokes all sessions for a specific application for the user associated with the provided access token and appID.
// - RevokeAllSession: Revokes all sessions for the user associated with the provided access token and appID.
// - BlockUser: Blocks a user with the specified email and username, and revokes all active sessions for the user.
//
// The AuthService struct also defines various error variables for common authentication-related errors.
package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/FurmanovVitaliy/auth-grpc-service/internal/domain/models"
	"github.com/FurmanovVitaliy/auth-grpc-service/internal/storage"
	"github.com/FurmanovVitaliy/auth-grpc-service/pkg/jwt"
	"github.com/FurmanovVitaliy/auth-grpc-service/utils"
	"github.com/FurmanovVitaliy/logger"
	"github.com/markbates/goth"
)

type AuthService struct {
	log             *slog.Logger
	userProvider    UserProvider
	appProvider     AppProvider
	sessionProvider SessionProvider
	accessTokenTTL  time.Duration
	refreshTokenTTL time.Duration
}

type UserProvider interface {
	Register(ctx context.Context, email, username, passHash, avatarURL, provider string) (err error)
	UserByEmail(ctx context.Context, email string) (user models.User, err error)
	UserByID(ctx context.Context, userID int64) (user models.User, err error)
	Update(ctx context.Context, userID int64, email, username, passHash, avatarURL *string, isBlocked *bool) error
}

type AppProvider interface {
	App(ctx context.Context, appID int32) (app models.App, err error)
}

type SessionProvider interface {
	Create(ctx context.Context, key models.SessionKey, appName, userIP, userAgent, refreshHash, refreshSecret string, exp time.Time) error
	GetByID(ctx context.Context, key models.SessionKey) (models.Session, error)
	GetByParam(ctx context.Context, key models.SessionKey) ([]models.Session, error)
	Revoke(ctx context.Context, sessionID string) error
	SaveOAuthSession(ctx context.Context, appID int32, provider, session, state string) error
	GetOAuthSession(ctx context.Context, provider, state string) (models.OAuthSession, error)
}

var (
	ErrEmailAlreadyExists    = errors.New("the specified email is already registered")
	ErrUsernameAlreadyExists = errors.New("the specified username is already taken")
	ErrInvalidCredentials    = errors.New("invalid credentials")
	ErrUserBlocked           = errors.New("the user account has been blocked by the administration")
	ErrSessionRevoked        = errors.New("session revoked or invalid")
	ErrSessionNotFound       = errors.New("session not found")
	ErrInvalidToken          = errors.New("invalid token, please log in again")
	ErrUserNotFound          = errors.New("user not found")
	ErrProviderNotSupported  = errors.New("authentication provider not supported")
	ErrLocalAccountExists    = errors.New("a local account is already registered with this email")
	ErrNotAdmin              = errors.New("the user does not have sufficient permissions to perform this operation")
	ErrBlockUserFailed       = errors.New("failed to block user")
)

// New creates a new instance of the Auth service.
func New(
	log *slog.Logger,
	userProvider UserProvider,
	appProvider AppProvider,
	sessionProvider SessionProvider,
	accessTokenTTL time.Duration,
	refreshTokenTTL time.Duration,
) *AuthService {
	return &AuthService{
		log:             log,
		userProvider:    userProvider,
		appProvider:     appProvider,
		sessionProvider: sessionProvider,
		accessTokenTTL:  accessTokenTTL,
		refreshTokenTTL: refreshTokenTTL,
	}
}

// Register: Registers a new user with the provided email, username, and password.
func (a *AuthService) Register(ctx context.Context, email, username, password string) (err error) {
	const op = "auth.Auth.Register"
	log := a.log.With(
		logger.StringAttr("op", op),
		logger.StringAttr("email", utils.MaskEmail(email)),
		logger.StringAttr("username", username),
	)

	passHash, err := utils.HashPassword(password)
	if err != nil {
		log.Error("failed to hash the password", logger.ErrAttr(err))
		return err
	}

	if err = a.userProvider.Register(ctx, email, username, passHash, "", "local"); err != nil {
		log.Error("failed to register the user", logger.ErrAttr(err))
		if errors.Is(err, storage.ErrEmailAlreadyExists) {
			return fmt.Errorf("%s: %w", op, ErrEmailAlreadyExists)
		}
		if errors.Is(err, storage.ErrUsenameAlreadyExists) {
			return fmt.Errorf("%s: %w", op, ErrUsernameAlreadyExists)
		}
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("new user successfully registered")

	return nil
}

func (a *AuthService) Login(ctx context.Context, email, password string, appID int32, userIP, userAgent string) (user models.User, resp models.LoginResponse, err error) {
	const op = "auth.Auth.Login"
	log := a.log.With(
		logger.StringAttr("op", op),
		logger.Int32Attr("app_id", appID),
		logger.StringAttr("email", utils.MaskEmail(email)),
	)

	user, err = a.userProvider.UserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return models.User{}, models.LoginResponse{}, ErrUserNotFound
		}
		log.Error("failed to get the user", logger.ErrAttr(err))
		return models.User{}, models.LoginResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	if err = utils.ComparePassword(user.PassHash, password); err != nil {
		return models.User{}, models.LoginResponse{}, ErrInvalidCredentials
	}

	if user.IsBlocked {
		return models.User{}, models.LoginResponse{}, ErrUserBlocked
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		log.Error("failed to get the app", logger.ErrAttr(err))
		return models.User{}, models.LoginResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	resp, err = a.createTokensAndSession(ctx, user, app, userIP, userAgent)
	if err != nil {
		log.Error("failed to create tokens and session", logger.ErrAttr(err))
		return models.User{}, models.LoginResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	return user, resp, nil
}

func (a *AuthService) Logout(ctx context.Context, sessionID string) error {
	const op = "auth.Auth.Logout"
	log := a.log.With(
		logger.StringAttr("op", op),
		logger.StringAttr("session_id", sessionID),
	)

	err := a.sessionProvider.Revoke(ctx, sessionID)
	if err != nil {
		log.Error("failed to delete the session", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (a *AuthService) RefreshToken(ctx context.Context, refreshToken, ip, agent string) (models.RefreshTokenResponse, error) {
	const op = "auth.Auth.RefreshToken"
	log := a.log.With(
		logger.StringAttr("op", op),
	)
	//TODO :metadata validation (user ip and agent)
	claims, err := jwt.ExtractUnverifiedRefreshTokenClaims(refreshToken)
	if err != nil {
		log.Error("failed to extract claims from the token", logger.ErrAttr(err))
		return models.RefreshTokenResponse{}, ErrInvalidToken
	}
	key := models.SessionKey{
		SessionID: claims.SID,
		UserID:    claims.UID,
		AppID:     claims.AID,
	}

	session, err := a.sessionProvider.GetByID(ctx, key)
	if err != nil {
		log.Error("failed to find session", logger.ErrAttr(err))
		return models.RefreshTokenResponse{}, ErrSessionNotFound
	}

	if session.Status != 0 {
		log.Warn("session is not active")
		return models.RefreshTokenResponse{}, ErrSessionRevoked
	}

	claims, err = jwt.VerifyRefreshToken(refreshToken, session.RefreshSecret)
	if err != nil {
		log.Error("failed to verify the token", logger.ErrAttr(err))
		return models.RefreshTokenResponse{}, ErrInvalidToken
	}

	if err = utils.VerifyTokenHash(refreshToken, session.RefreshToken); err != nil {
		return models.RefreshTokenResponse{}, ErrInvalidToken
	}

	app, err := a.appProvider.App(ctx, claims.AID)
	if err != nil {
		log.Error("failed to get the app", logger.ErrAttr(err))
		return models.RefreshTokenResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	user, err := a.userProvider.UserByID(ctx, claims.UID)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return models.RefreshTokenResponse{}, ErrUserNotFound
		}
		log.Error("failed to get the user", logger.ErrAttr(err))
		return models.RefreshTokenResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	if user.IsBlocked {
		return models.RefreshTokenResponse{}, ErrUserBlocked
	}

	access, ac, err := jwt.CreateAccessToken(user.ID, app.ID, user.Email, user.Role, a.accessTokenTTL, app.Secret)
	if err != nil {
		log.Error("failed to gen access token", logger.ErrAttr(err))
		return models.RefreshTokenResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	return models.RefreshTokenResponse{
		AccessToken:          access,
		AccessTokenExpiresAt: ac.ExpiresAt.Time,
	}, nil
}

func (a *AuthService) OAuth(ctx context.Context, providerName string, appID int32) (authURL string, err error) {
	const op = "auth.Auth.OAuth"
	log := a.log.With(
		logger.StringAttr("op", op),
		logger.StringAttr("provider", providerName),
	)
	state := utils.GenerateSimpleID()
	provider, err := goth.GetProvider(strings.ToLower(providerName))
	if err != nil {
		return "", ErrProviderNotSupported
	}

	session, err := provider.BeginAuth(state)
	if err != nil {
		log.Error("failed to begin auth", logger.ErrAttr(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	sessionString := session.Marshal()

	err = a.sessionProvider.SaveOAuthSession(ctx, appID, providerName, sessionString, state)
	if err != nil {
		log.Error("failed to save oauth session", logger.ErrAttr(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	authURL, err = session.GetAuthURL()
	if err != nil {
		log.Error("failed to get auth url", logger.ErrAttr(err))
		return "", fmt.Errorf("%s: %w", op, err)
	}
	return authURL, nil
}

func (a *AuthService) OAuthCallback(ctx context.Context, providerName, code, state, userIP, userAgent string) (user models.User, resp models.LoginResponse, err error) {
	const op = "auth.Auth.OAuthCallback"
	log := a.log.With(
		logger.StringAttr("op", op),
		logger.StringAttr("provider", providerName),
	)
	user, appID, err := a.completOAuthAuth(ctx, providerName, code, state)
	if err != nil {
		return models.User{}, models.LoginResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	existingUser, err := a.handleOAuthUser(ctx, user.Email, user.Username, user.Avatar, providerName)
	if err != nil {
		return models.User{}, models.LoginResponse{}, err
	}

	if existingUser.IsBlocked {
		return models.User{}, models.LoginResponse{}, ErrUserBlocked
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		log.Error("failed to get the app", logger.ErrAttr(err))
		return models.User{}, models.LoginResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	resp, err = a.createTokensAndSession(ctx, existingUser, app, userIP, userAgent)
	if err != nil {
		log.Error("failed to create tokens and session", logger.ErrAttr(err))
		return models.User{}, models.LoginResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	return existingUser, resp, nil
}

func (a *AuthService) Sessions(ctx context.Context, accessToken string, appID int32) ([]models.SessionResponce, error) {
	const op = "auth.Auth.Sessions"
	log := a.log.With(
		logger.StringAttr("op", op),
		logger.Int32Attr("app_id", appID),
	)
	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		log.Error("failed to get the app", logger.ErrAttr(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	claims, err := jwt.VerifyAccessToken(accessToken, app.Secret)
	if err != nil {
		return nil, ErrInvalidToken
	}

	sessions, err := a.sessionProvider.GetByParam(ctx, models.SessionKey{UserID: claims.UID})
	if err != nil {
		log.Error("failed to get sessions", logger.ErrAttr(err))
		return nil, fmt.Errorf("%s: %w", op, err)
	}

	var res []models.SessionResponce

	for _, s := range sessions {
		res = append(res, models.SessionResponce{
			SessionID:    s.ID,
			UserIP:       s.IPAddress,
			UserAgent:    s.UserAgent,
			UserDevice:   "unknown",
			AppName:      s.AppName,
			Status:       s.Status,
			CreatedAt:    s.CreatedAt,
			LastActivity: *s.UpdatedAt,
		})
	}
	return res, nil

}

func (a *AuthService) RevokeSession(ctx context.Context, accessToken string, appID int32, sessionID string) error {
	const op = "auth.Auth.RevokeSession"
	log := a.log.With(
		logger.StringAttr("op", op),
		logger.StringAttr("session_id", sessionID),
	)

	app, err := a.appProvider.App(ctx, appID)

	if err != nil {
		log.Error("failed to get the app", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	_, err = jwt.VerifyAccessToken(accessToken, app.Secret)
	if err != nil {
		log.Error("failed to verify the token", logger.ErrAttr(err))
		return ErrInvalidToken
	}

	if err = a.sessionProvider.Revoke(ctx, sessionID); err != nil {
		log.Error("failed to revoke the session", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func (a *AuthService) RevokeAppSession(ctx context.Context, accessToken string, appID, targetAppID int32) error {
	const op = "auth.Auth.RevokeAppSession"
	log := a.log.With(
		logger.StringAttr("op", op),
		logger.Int32Attr("target_app_id", targetAppID),
	)
	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		log.Error("failed to get the app", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	claims, err := jwt.VerifyAccessToken(accessToken, app.Secret)
	if err != nil {
		log.Error("failed to verify the token", logger.ErrAttr(err))
		return ErrInvalidToken
	}

	sessions, err := a.sessionProvider.GetByParam(ctx, models.SessionKey{AppID: targetAppID, UserID: claims.UID})
	if err != nil {
		log.Error("failed to get sessions", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	for _, s := range sessions {
		err := a.sessionProvider.Revoke(ctx, s.ID)
		if err != nil {
			log.Error("failed to revoke the session", logger.ErrAttr(err))
		}
	}
	return nil
}

func (a *AuthService) RevokeAllSession(ctx context.Context, accessToken string, appID int32) error {
	const op = "auth.Auth.RevokeAllSession"
	log := a.log.With(
		logger.StringAttr("op", op),
	)
	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		log.Error("failed to get the app", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	claims, err := jwt.VerifyAccessToken(accessToken, app.Secret)
	if err != nil {
		log.Error("failed to verify the token", logger.ErrAttr(err))
		return ErrInvalidToken
	}

	sessions, err := a.sessionProvider.GetByParam(ctx, models.SessionKey{UserID: claims.UID})
	if err != nil {
		log.Error("failed to get sessions", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	for _, s := range sessions {
		err := a.sessionProvider.Revoke(ctx, s.ID)
		if err != nil {
			log.Error("failed to revoke the session", logger.ErrAttr(err))
		}
	}

	return nil
}

func (a *AuthService) BlockUser(ctx context.Context, appID int32, accessToken, email string) error {
	const op = "auth.Auth.BlockUser"
	log := a.log.With(
		logger.StringAttr("op", op),
		logger.StringAttr("email", utils.MaskEmail(email)),
	)
	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		log.Error("failed to get the app", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	claims, err := jwt.VerifyAccessToken(accessToken, app.Secret)
	if err != nil {
		log.Error("failed to verify the token", logger.ErrAttr(err))
		return ErrInvalidToken
	}

	if claims.Role != 1 {
		return ErrNotAdmin
	}

	user, err := a.userProvider.UserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			return ErrUserNotFound
		}
		log.Error("failed to get the user", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	sessions, err := a.sessionProvider.GetByParam(ctx, models.SessionKey{UserID: user.ID})
	if err != nil {
		log.Error("failed to get sessions", logger.ErrAttr(err))
		return fmt.Errorf("%s: %w", op, err)
	}

	isBloked := true

	if err := a.userProvider.Update(ctx, user.ID, nil, nil, nil, nil, &isBloked); err != nil {
		return ErrBlockUserFailed
	}

	for _, s := range sessions {
		err := a.sessionProvider.Revoke(ctx, s.ID)
		if err != nil {
			log.Error("failed to terminate active sessions of the blocked user", logger.ErrAttr(err))
			continue
		}
	}

	return nil
}

func (a *AuthService) completOAuthAuth(ctx context.Context, providerName string, code, state string) (models.User, int32, error) {
	const op = "auth.Auth.completOAuthAuth"
	log := a.log.With(
		logger.StringAttr("op", op),
		logger.StringAttr("provider", providerName),
	)

	provider, err := goth.GetProvider(providerName)
	if err != nil {
		log.Error("failed to get provider", logger.ErrAttr(err))
		return models.User{}, 0, fmt.Errorf("%s: %w", op, err)
	}

	oauthSession, err := a.sessionProvider.GetOAuthSession(ctx, providerName, state)
	if err != nil {
		log.Error("failed to get session", logger.ErrAttr(err))
		return models.User{}, 0, fmt.Errorf("%s: %w", op, err)
	}

	if oauthSession.Status != 0 {
		log.Warn("session is not active")
		return models.User{}, 0, fmt.Errorf("%s: %w", op, err)
	}

	session, err := provider.UnmarshalSession(oauthSession.Session)
	if err != nil {
		log.Error("failed to unmarshal session", logger.ErrAttr(err))
		return models.User{}, 0, fmt.Errorf("%s: %w", op, err)
	}

	_, err = session.Authorize(provider, url.Values{"code": {code}, "state": {state}})
	if err != nil {
		log.Error("failed to authorize", logger.ErrAttr(err))
		return models.User{}, 0, fmt.Errorf("%s: %w", op, err)
	}

	userInfo, err := provider.FetchUser(session)
	if err != nil {
		log.Error("failed to fetch user", logger.ErrAttr(err))
		return models.User{}, 0, fmt.Errorf("%s: %w", op, err)
	}

	email := userInfo.Email
	if email == "" {
		log.Warn("OAuth provider did not return an email")
		email = fmt.Sprintf("%s_%s@oauth.mock", providerName, userInfo.UserID)
	}

	username := utils.GenerateUsername(userInfo)

	return models.User{
		Email:    email,
		Username: username,
		Provider: providerName,
		Avatar:   userInfo.AvatarURL,
	}, oauthSession.AppID, nil
}

func (a *AuthService) handleOAuthUser(ctx context.Context, email, username, avatar, provider string) (models.User, error) {
	const op = "auth.Auth.handleOAuthUser"
	log := a.log.With(
		logger.StringAttr("op", op),
		logger.StringAttr("email", utils.MaskEmail(email)),
		logger.StringAttr("username", username),
	)

	existingUser, err := a.userProvider.UserByEmail(ctx, email)
	if err != nil && !errors.Is(err, storage.ErrUserNotFound) {
		log.Error("failed to get the user", logger.ErrAttr(err))
		return models.User{}, fmt.Errorf("%s: %w", op, err)
	}

	if err == nil {
		if existingUser.Provider == "local" {
			return models.User{}, ErrLocalAccountExists
		}
		return existingUser, nil
	}

	if err := a.userProvider.Register(ctx, email, username, "", avatar, provider); err != nil {
		return models.User{}, err
	}

	return a.userProvider.UserByEmail(ctx, email)
}

func (a *AuthService) createTokensAndSession(ctx context.Context, user models.User, app models.App, userIP, userAgent string) (models.LoginResponse, error) {
	const op = "auth.Auth.generateTokensAndSession"
	log := a.log.With(
		logger.StringAttr("op", op),
	)

	refreshSecret, err := utils.GenerateSecret(32)
	if err != nil {
		log.Error("failed to gen refresh secret", logger.ErrAttr(err))
		return models.LoginResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	sessionID, err := utils.GenerateID()
	if err != nil {
		log.Error("failed to gen session id", logger.ErrAttr(err))
		return models.LoginResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	access, ac, err := jwt.CreateAccessToken(user.ID, app.ID, user.Email, user.Role, a.accessTokenTTL, app.Secret)
	if err != nil {
		log.Error("failed to gen access token", logger.ErrAttr(err))
		return models.LoginResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	refresh, rc, err := jwt.CreateRefreshToken(user.ID, app.ID, sessionID, a.refreshTokenTTL, refreshSecret)
	if err != nil {
		log.Error("failed to gen refresh token", logger.ErrAttr(err))
		return models.LoginResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	key := models.SessionKey{
		AppID:     app.ID,
		UserID:    user.ID,
		SessionID: sessionID,
	}

	if err = a.sessionProvider.Create(ctx, key, app.Name, userIP, userAgent, utils.HashToken(refresh), refreshSecret, rc.ExpiresAt.Time); err != nil {
		log.Error("failed to create session", logger.ErrAttr(err))
		return models.LoginResponse{}, fmt.Errorf("%s: %w", op, err)
	}

	return models.LoginResponse{
		SessionID:             sessionID,
		AccessToken:           access,
		RefreshToken:          refresh,
		AccessTokenExpiresAt:  ac.ExpiresAt.Time,
		RefreshTokenExpiresAt: rc.ExpiresAt.Time,
	}, nil
}
