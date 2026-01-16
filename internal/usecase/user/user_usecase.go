package user

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/yourusername/authservice/internal/domain"
	"github.com/yourusername/authservice/internal/pkg/hasher"
)

var (
	ErrUserNotFound = errors.New("user not found")
)

type userUseCase struct {
	userRepo domain.UserRepository
	hasher   hasher.Hasher
}

func NewUserUseCase(userRepo domain.UserRepository, hasher hasher.Hasher) UseCase {
	return &userUseCase{
		userRepo: userRepo,
		hasher:   hasher,
	}
}

func (uc *userUseCase) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	user, err := uc.userRepo.GetByID(id)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (uc *userUseCase) Update(ctx context.Context, id uuid.UUID, input UpdateInput) (*domain.User, error) {
	user, err := uc.userRepo.GetByID(id)
	if err != nil {
		return nil, ErrUserNotFound
	}

	if input.Email != "" {
		user.Email = input.Email
	}

	if input.Password != "" {
		hash, err := uc.hasher.Hash(input.Password)
		if err != nil {
			return nil, err
		}
		user.PasswordHash = hash
	}

	if err := uc.userRepo.Update(user); err != nil {
		return nil, err
	}

	return user, nil
}

func (uc *userUseCase) Delete(ctx context.Context, id uuid.UUID) error {
	return uc.userRepo.Delete(id)
}
