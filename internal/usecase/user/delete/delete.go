package delete

import (
	"context"

	"github.com/google/uuid"

	"github.com/yourusername/authservice/internal/domain"
	"github.com/yourusername/authservice/internal/pkg/logger"
)

type Params struct {
	UserRepo    domain.UserRepository
	SessionRepo domain.SessionRepository
	TokenRepo   domain.TokenRepository
}

type Payload struct {
	UserID uuid.UUID
}

type UseCase struct {
	ctx context.Context
	*Params
	*Payload
}

func New(ctx context.Context, params *Params, payload *Payload) *UseCase {
	return &UseCase{ctx: ctx, Params: params, Payload: payload}
}

func (u *UseCase) Execute() error {
	if err := u.TokenRepo.DeleteAllUserTokens(u.ctx, u.UserID); err != nil {
		logger.Warn().Err(err).Str("user_id", u.UserID.String()).Msg("failed to delete user tokens")
	}

	if err := u.SessionRepo.DeleteAllUserSessions(u.ctx, u.UserID); err != nil {
		logger.Warn().Err(err).Str("user_id", u.UserID.String()).Msg("failed to delete user sessions")
	}

	if err := u.UserRepo.Delete(u.ctx, u.UserID); err != nil {
		logger.Error().Err(err).Str("user_id", u.UserID.String()).Msg("failed to delete user")
		return err
	}

	logger.Info().Str("user_id", u.UserID.String()).Msg("user deleted successfully")

	return nil
}
