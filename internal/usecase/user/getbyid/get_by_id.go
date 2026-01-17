package getbyid

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/yourusername/authservice/internal/domain"
	"github.com/yourusername/authservice/internal/pkg/logger"
)

var (
	ErrUserNotFound = errors.New("user not found")
)

type Params struct {
	UserRepo domain.UserRepository
}

type Payload struct {
	UserID uuid.UUID
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
	user, err := u.UserRepo.GetByID(u.ctx, u.UserID)
	if err != nil {
		logger.Debug().Str("user_id", u.UserID.String()).Msg("user not found")
		return nil, ErrUserNotFound
	}

	return &Result{User: user}, nil
}
