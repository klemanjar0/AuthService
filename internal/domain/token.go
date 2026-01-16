package domain

import (
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
	StoreRefreshToken(token *RefreshToken) error
	GetRefreshToken(token string) (*RefreshToken, error)
	DeleteRefreshToken(token string) error
	DeleteAllUserTokens(userID uuid.UUID) error
}
