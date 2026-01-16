package auth

import (
	"context"

	"github.com/google/uuid"
	"github.com/yourusername/authservice/internal/domain"
)

type RegisterInput struct {
	Email    string
	Password string
}

type LoginInput struct {
	Email     string
	Password  string
	UserAgent string
	IP        string
}

type AuthResult struct {
	User      *domain.User
	Tokens    *domain.TokenPair
	SessionID string
}

type RefreshInput struct {
	RefreshToken string
}

type UseCase interface {
	Register(ctx context.Context, input RegisterInput) (*AuthResult, error)
	Login(ctx context.Context, input LoginInput) (*AuthResult, error)
	Refresh(ctx context.Context, input RefreshInput) (*domain.TokenPair, error)
	Logout(ctx context.Context, userID uuid.UUID, sessionID string) error
	LogoutAll(ctx context.Context, userID uuid.UUID) error
	ValidateSession(ctx context.Context, sessionID string) (*domain.Session, error)
}
