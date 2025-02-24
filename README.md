# auth-grpc-service

## Overview
`auth-grpc-service` is a gRPC-based authentication service that provides secure multi-application user authentication and session management. It supports OAuth, JWT-based authentication, and session validation to ensure security and flexibility in modern distributed systems.

## Features
- **Multi-application authentication**
- **OAuth provider support** (Google, GitHub, Facebook, Apple)
- **JWT-based access tokens**
- **Session management with IP & User-Agent tracking**
- **User registration and login with hashed passwords**
- **Security mechanisms to prevent session hijacking**

## Technologies Used
- **Golang** (Core service implementation)
- **gRPC** (Communication protocol)
- **PostgreSQL** (User and session storage)
- **Redis** (Optional for session caching)
- **JWT** (Access and refresh tokens)
- **Goth** (OAuth integration)
- **slog** (Logging)

## Installation
### Prerequisites
- Go 1.21+
- PostgreSQL database
- Redis (optional for session caching)

### Clone the repository
```sh
git clone https://github.com/FurmanovVitaliy/auth-grpc-service.git
cd auth-grpc-service
```

### Configure Environment
Create a `local.yaml` file with the necessary database and security configurations.
You can find an example in `config/example.yaml`

### Run the service
```sh
go run cmd/sso/main.go
```

## API Endpoints
The service exposes gRPC endpoints for authentication and session management. The main available methods include:

### User Authentication
- `Register(email, username, password) -> (success, message)`
- `Login(email, password, appID) -> (user, session_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at, message)`
- `Logout(sessionID) -> (success, message)`
- `RefreshToken(refreshToken) -> (newAccessToken, access_token_expires_at)`

### OAuth Support
- `OAuth(provider, appID) -> (authURL, provider)`
- `GithubCallback(code, state) -> (user, session_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at, message)`

### Session Management
- `ActiveSessions(accessToken, appID) -> ([]Session)`
- `RevokeSession(sessionID, accessToken, appID) -> (success, message)`
- `RevokeAppSessions(accessToken, appID, targetAppID) -> (success, message)`
- `RevokeAllSessions(accessToken, appID) -> (success, message)`

### Admin Operations
- `BlockUser(email, accessToken, appID) -> (success, message)`

## Security Features
- **Hashed passwords** using bcrypt
- **IP & User-Agent tracking** for session protection
- **Session invalidation on suspicious activity**
- **Token expiration handling**

## License
This project is licensed under the MIT License.

## Author
[Vitalii Furmanov](https://github.com/FurmanovVitaliy)

