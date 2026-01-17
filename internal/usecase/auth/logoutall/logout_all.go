package logoutall

import (
	"context"

	"github.com/google/uuid"

	"github.com/yourusername/authservice/internal/domain"
	"github.com/yourusername/authservice/internal/pkg/logger"
)

type Params struct {
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
		logger.Error().
			Err(err).
			Str("user_id", u.UserID.String()).
			Msg("failed to delete all user tokens")
		return err
	}

	if err := u.SessionRepo.DeleteAllUserSessions(u.ctx, u.UserID); err != nil {
		logger.Error().
			Err(err).
			Str("user_id", u.UserID.String()).
			Msg("failed to delete all user sessions")
		return err
	}

	logger.Info().
		Str("user_id", u.UserID.String()).
		Msg("user logged out from all devices")

	return nil
}
