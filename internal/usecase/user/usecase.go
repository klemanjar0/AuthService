package user

import (
	"context"

	"github.com/google/uuid"
	"github.com/yourusername/authservice/internal/domain"
)

type UpdateInput struct {
	Email    string
	Password string
}

type UseCase interface {
	GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error)
	Update(ctx context.Context, id uuid.UUID, input UpdateInput) (*domain.User, error)
	Delete(ctx context.Context, id uuid.UUID) error
}
