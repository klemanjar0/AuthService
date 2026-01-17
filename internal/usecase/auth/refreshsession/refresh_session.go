package refreshsession

import (
	"context"
	"errors"
	"time"

	"github.com/yourusername/authservice/internal/domain"
	"github.com/yourusername/authservice/internal/pkg/logger"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
)

type Params struct {
	SessionRepo domain.SessionRepository
	SessionExp  time.Duration
}

type Payload struct {
	SessionID string
}

type Result struct {
	Session *domain.Session
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
	session, err := u.SessionRepo.Get(u.ctx, u.SessionID)
	if err != nil {
		logger.Debug().Str("session_id", u.SessionID).Msg("session not found")
		return nil, ErrSessionNotFound
	}

	if time.Now().After(session.ExpiresAt) {
		_ = u.SessionRepo.Delete(u.ctx, u.SessionID)
		logger.Debug().Str("session_id", u.SessionID).Msg("session expired")
		return nil, ErrSessionExpired
	}

	session, err = u.SessionRepo.Refresh(u.ctx, u.SessionID, u.SessionExp)
	if err != nil {
		logger.Error().Err(err).Str("session_id", u.SessionID).Msg("failed to refresh session")
		return nil, err
	}

	logger.Info().
		Str("session_id", u.SessionID).
		Str("user_id", session.UserID.String()).
		Time("new_expiry", session.ExpiresAt).
		Msg("session refreshed successfully")

	return &Result{Session: session}, nil
}
