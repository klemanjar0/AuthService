package domain

import (
	"context"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type AccessTokenClaims struct {
	jwt.RegisteredClaims
	UserID uuid.UUID `json:"user_id"`
	Email  string    `json:"email"`
}

type RefreshToken struct {
	Token     string    `json:"token"`
	UserID    uuid.UUID `json:"user_id"`
	ExpiresAt time.Time `json:"expires_at"`
}

type TokenRepository interface {
	StoreRefreshToken(ctx context.Context, token *RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, token string) error
	DeleteAllUserTokens(ctx context.Context, userID uuid.UUID) error
}
