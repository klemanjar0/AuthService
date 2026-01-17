package logout

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"

	"github.com/yourusername/authservice/internal/domain"
	"github.com/yourusername/authservice/internal/pkg/logger"
)

type Params struct {
	SessionRepo domain.SessionRepository
	TokenRepo   domain.TokenRepository
	AuditRepo   domain.AuditLogRepository
}

type Payload struct {
	UserID       uuid.UUID
	SessionID    string
	RefreshToken string
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
	if u.SessionID != "" {
		if err := u.SessionRepo.Delete(u.SessionID); err != nil {
			logger.Warn().
				Err(err).
				Str("session_id", u.SessionID).
				Msg("failed to delete session")
		}
	}

	if u.RefreshToken != "" {
		if err := u.TokenRepo.DeleteRefreshToken(u.RefreshToken); err != nil {
			logger.Warn().
				Err(err).
				Msg("failed to delete refresh token")
		}
	}

	u.logAudit(&u.UserID, domain.EventUserLogout, map[string]any{"session_id": u.SessionID})

	logger.Info().
		Str("user_id", u.UserID.String()).
		Str("session_id", u.SessionID).
		Msg("user logged out successfully")

	return nil
}

func (u *UseCase) logAudit(userID *uuid.UUID, eventType string, payload map[string]any) {
	if u.AuditRepo == nil {
		return
	}
	payloadBytes, _ := json.Marshal(payload)
	_ = u.AuditRepo.Create(&domain.AuditLog{
		UserID:    userID,
		EventType: eventType,
		Payload:   payloadBytes,
	})
}
