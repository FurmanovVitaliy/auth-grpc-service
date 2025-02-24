package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/FurmanovVitaliy/auth-grpc-service/internal/domain/models"
	"github.com/FurmanovVitaliy/auth-grpc-service/internal/services/auth"
	"github.com/FurmanovVitaliy/auth-grpc-service/utils"
	sso "github.com/FurmanovVitaliy/grpc-api/gen/go/sso_v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Auth interface {
	Register(ctx context.Context, email, username, password string) (err error)
	Login(ctx context.Context, email, password string, appID int32, userIP, userAgent string) (user models.User, resp models.LoginResponse, err error)
	Logout(ctx context.Context, sessionID string) error
	RefreshToken(ctx context.Context, refreshToken, userIP, userAgent string) (models.RefreshTokenResponse, error)
	OAuth(ctx context.Context, providerName string, appID int32) (authURL string, err error)
	OAuthCallback(ctx context.Context, providerName, code, state, userIP, userAgent string) (user models.User, resp models.LoginResponse, err error)
	Sessions(ctx context.Context, accessToken string, appID int32) ([]models.SessionResponce, error)
	RevokeSession(ctx context.Context, accessToken string, appID int32, sessionID string) error
	RevokeAppSession(ctx context.Context, accessToken string, appID, targetAppID int32) error
	RevokeAllSession(ctx context.Context, accessToken string, appID int32) error
	BlockUser(ctx context.Context, appID int32, accessToken, email string) error
}
type serverAPI struct {
	sso.UnimplementedAuthServer
	auth Auth
}

var (
	ErrInternal               = status.Error(codes.Internal, "AS-000: An unexpected internal error occurred")
	ErrEmailAlreadyExists     = status.Error(codes.AlreadyExists, "AS-001: This email is already associated with an existing account")
	ErrUsernameTaken          = status.Error(codes.AlreadyExists, "AS-002: This username is already taken")
	ErrInvalidCredentials     = status.Error(codes.Unauthenticated, "AS-003: Invalid email or password")
	ErrUserBlocked            = status.Error(codes.PermissionDenied, "AS-004: This account has been blocked by the administrator")
	ErrSessionExpired         = status.Error(codes.Unauthenticated, "AS-005: The session has expired or been revoked. Please log in again")
	ErrInvalidToken           = status.Error(codes.Unauthenticated, "AS-006: The token is invalid or has expired. Please log in again")
	ErrUnsupportedProvider    = status.Error(codes.FailedPrecondition, "AS-007: This authentication provider is not supported at the moment")
	ErrLocalAccountExists     = status.Error(codes.AlreadyExists, "AS-008: A local account is already registered with this email")
	ErrInsufficientPrivileges = status.Error(codes.PermissionDenied, "AS-009: You do not have the necessary permissions to perform this action")
	ErrServerError            = status.Error(codes.Internal, "AS-010: Internal server error")
)

func Register(server *grpc.Server, auth Auth) {
	sso.RegisterAuthServer(server, &serverAPI{auth: auth})
}

func (s *serverAPI) Register(ctx context.Context, req *sso.RegisterRequest) (*sso.RegisterResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	err := s.auth.Register(ctx, req.GetEmail(), req.GetUsername(), req.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrEmailAlreadyExists) {
			return nil, ErrEmailAlreadyExists
		}
		if errors.Is(err, auth.ErrUsernameAlreadyExists) {
			return nil, ErrUsernameTaken
		}

		return nil, ErrInternal
	}
	return &sso.RegisterResponse{
		Success: true,
		Message: "User registration completed successfully",
	}, nil
}

func (s *serverAPI) Login(ctx context.Context, req *sso.LoginRequest) (*sso.LoginResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	userAgent, UserIP := utils.ExtractRequestMetadata(ctx)
	user, resp, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), req.GetAppId(), UserIP, userAgent)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredentials) {
			return nil, ErrInvalidCredentials
		}
		if errors.Is(err, auth.ErrUserBlocked) {
			return nil, ErrUserBlocked
		}
		return nil, ErrInternal
	}
	return &sso.LoginResponse{
		User: &sso.User{
			Email:     user.Email,
			Username:  user.Username,
			AvatarUrl: user.Avatar,
			Role:      sso.Role(user.Role),
		},
		SessionId:             resp.SessionID,
		AccessToken:           resp.AccessToken,
		RefreshToken:          resp.RefreshToken,
		AccessTokenExpiresAt:  timestamppb.New(resp.AccessTokenExpiresAt),
		RefreshTokenExpiresAt: timestamppb.New(resp.RefreshTokenExpiresAt),
		Message:               "User logged in successfully",
	}, nil
}

func (s *serverAPI) Logout(ctx context.Context, req *sso.LogoutRequest) (*sso.LogoutResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	err := s.auth.Logout(ctx, req.GetSessionId())
	if err != nil {
		return nil, status.Error(codes.Internal, "internal server error")
	}
	return &sso.LogoutResponse{
		Success: true,
		Message: "User logged out successfully",
	}, nil
}

func (s *serverAPI) RefreshToken(ctx context.Context, req *sso.RefreshTokenRequest) (*sso.RefreshTokenResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	userAgent, UserIP := utils.ExtractRequestMetadata(ctx)
	resp, err := s.auth.RefreshToken(ctx, req.GetRefreshToken(), UserIP, userAgent)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidToken) || errors.Is(err, auth.ErrUserNotFound) {
			return nil, ErrInvalidToken
		}
		if errors.Is(err, auth.ErrSessionRevoked) || errors.Is(err, auth.ErrSessionNotFound) {
			return nil, ErrSessionExpired
		}
		if errors.Is(err, auth.ErrUserBlocked) {
			return nil, ErrUserBlocked
		}
		return nil, ErrInternal
	}
	return &sso.RefreshTokenResponse{
		AccessToken:          resp.AccessToken,
		AccessTokenExpiresAt: timestamppb.New(resp.AccessTokenExpiresAt),
	}, nil
}

func (s *serverAPI) OAuth(ctx context.Context, req *sso.OAuthRequest) (*sso.OAuthResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	authURL, err := s.auth.OAuth(ctx, strings.ToLower(req.GetProvider().String()), req.GetAppId())
	if err != nil {
		if errors.Is(err, auth.ErrProviderNotSupported) {
			return nil, ErrUnsupportedProvider
		}
		return nil, ErrInternal
	}
	return &sso.OAuthResponse{
		AuthUrl:  authURL,
		Provider: req.GetProvider().String(),
	}, nil
}

func (s *serverAPI) GithubCallback(ctx context.Context, req *sso.OAuthCallbackRequest) (*sso.OAuthCallbackResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	userAgent, userIP := utils.ExtractRequestMetadata(ctx)
	user, resp, err := s.auth.OAuthCallback(ctx, strings.ToLower(sso.OAuthProvider_GITHUB.String()), req.GetCode(), req.GetState(), userIP, userAgent)
	if err != nil {
		if errors.Is(err, auth.ErrLocalAccountExists) {
			return nil, ErrLocalAccountExists
		}

		if errors.Is(err, auth.ErrUserBlocked) {
			return nil, ErrUserBlocked
		}
		return nil, ErrInternal
	}
	return &sso.OAuthCallbackResponse{
		User: &sso.User{
			Email:     user.Email,
			Username:  user.Username,
			AvatarUrl: user.Avatar,
			Role:      sso.Role(user.Role),
		},
		SessionId:             resp.SessionID,
		AccessToken:           resp.AccessToken,
		RefreshToken:          resp.RefreshToken,
		AccessTokenExpiresAt:  timestamppb.New(resp.AccessTokenExpiresAt),
		RefreshTokenExpiresAt: timestamppb.New(resp.RefreshTokenExpiresAt),
		Message:               "User logged in successfully with GitHub",
	}, nil

}

func (s *serverAPI) ActiveSessions(ctx context.Context, req *sso.ActiveSessionsRequest) (*sso.ActiveSessionsResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	resp, err := s.auth.Sessions(ctx, req.GetAccessToken(), req.GetAppId())
	if err != nil {
		if errors.Is(err, auth.ErrInvalidToken) {
			return nil, ErrInvalidToken
		}
		return nil, ErrInternal
	}

	var activeSessions []*sso.Session
	for _, session := range resp {
		activeSessions = append(activeSessions, &sso.Session{
			SessionId:    session.SessionID,
			IpAddress:    session.UserIP,
			UserAgent:    session.UserAgent,
			Device:       session.UserDevice,
			AppName:      session.AppName,
			Status:       sso.SessionStatus(session.Status),
			CreatedAt:    timestamppb.New(session.CreatedAt),
			LastActivity: timestamppb.New(session.LastActivity),
		})
	}

	return &sso.ActiveSessionsResponse{
		Sessions: activeSessions,
	}, nil
}

func (s *serverAPI) RevokeSession(ctx context.Context, req *sso.RevokeSessionRequest) (*sso.RevokeSessionResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	if err := s.auth.RevokeSession(ctx, req.GetAccessToken(), req.GetAppId(), req.GetSessionId()); err != nil {
		if errors.Is(err, auth.ErrInvalidToken) {
			return nil, ErrInvalidToken
		}
		if errors.Is(err, auth.ErrSessionNotFound) {
			return nil, ErrSessionExpired
		}
		return nil, ErrInternal
	}
	return &sso.RevokeSessionResponse{
		Success: true,
		Message: fmt.Sprintf("Session with id %s revoked successfully", req.GetSessionId()),
	}, nil
}

func (s *serverAPI) RevokeAppSessions(ctx context.Context, req *sso.RevokeAppSessionsRequest) (*sso.RevokeAppSessionsResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}
	if err := s.auth.RevokeAppSession(ctx, req.GetAccessToken(), req.GetAppId(), req.GetTargetAppId()); err != nil {
		if errors.Is(err, auth.ErrInvalidToken) {
			return nil, ErrInvalidToken
		}
		return nil, ErrInternal
	}
	return &sso.RevokeAppSessionsResponse{
		Success: true,
		Message: fmt.Sprintf("Sessions for app id %d revoked successfully", req.GetTargetAppId()),
	}, nil
}

func (s *serverAPI) RevokeAllSessions(ctx context.Context, req *sso.RevokeAllSessionsRequest) (*sso.RevokeAllSessionsResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	if err := s.auth.RevokeAllSession(ctx, req.GetAccessToken(), req.GetAppId()); err != nil {
		if errors.Is(err, auth.ErrInvalidToken) {
			return nil, ErrInvalidToken
		}
		return nil, ErrInternal
	}

	return &sso.RevokeAllSessionsResponse{
		Success: true,
		Message: "All user sessions revoked successfully",
	}, nil
}

func (s *serverAPI) BlockUser(ctx context.Context, req *sso.BlockUserRequest) (*sso.BlockUserResponse, error) {
	if err := req.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request: %v", err)
	}

	if err := s.auth.BlockUser(ctx, req.GetAppId(), req.AccessToken, req.GetEmail()); err != nil {
		if errors.Is(err, auth.ErrInvalidToken) {
			return nil, ErrInvalidToken
		}
		if errors.Is(err, auth.ErrNotAdmin) {
			return nil, ErrInsufficientPrivileges
		}
		if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Errorf(codes.InvalidArgument, "failed to find user with provided email")
		}
		if errors.Is(err, auth.ErrBlockUserFailed) {
			return nil, status.Errorf(codes.Internal, "failed to block user with provided email")
		}
		return nil, ErrInternal
	}

	return &sso.BlockUserResponse{
		Success: true,
		Message: fmt.Sprintf("user with %s email successfully blocked", req.Email),
	}, nil
}
