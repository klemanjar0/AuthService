package update

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/yourusername/authservice/internal/domain"
	"github.com/yourusername/authservice/internal/pkg/hasher"
	"github.com/yourusername/authservice/internal/pkg/logger"
)

var (
	ErrUserNotFound = errors.New("user not found")
)

type Params struct {
	UserRepo domain.UserRepository
	Hasher   hasher.Hasher
}

type Payload struct {
	UserID   uuid.UUID
	Email    string
	Password string
}

type Result struct {
	User *domain.User
}

type UseCase struct {
	ctx context.Context
	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *UseCase {
	return &UseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *UseCase) Execute() (*Result, error) {
	user, err := u.UserRepo.GetByID(u.UserID)
	if err != nil {
		logger.Debug().Str("user_id", u.UserID.String()).Msg("user not found")
		return nil, ErrUserNotFound
	}

	if u.Email != "" {
		user.Email = u.Email
	}

	if u.Password != "" {
		hash, err := u.Hasher.Hash(u.Password)
		if err != nil {
			logger.Error().Err(err).Msg("failed to hash password")
			return nil, err
		}
		user.PasswordHash = hash
	}

	if err := u.UserRepo.Update(user); err != nil {
		logger.Error().Err(err).Str("user_id", u.UserID.String()).Msg("failed to update user")
		return nil, err
	}

	logger.Info().Str("user_id", u.UserID.String()).Msg("user updated successfully")

	return &Result{User: user}, nil
}
