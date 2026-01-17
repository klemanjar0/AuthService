package refresh

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/yourusername/authservice/internal/domain"
	"github.com/yourusername/authservice/internal/pkg/jwt"
	"github.com/yourusername/authservice/internal/pkg/logger"
)

var (
	ErrInvalidToken = errors.New("invalid or expired token")
)

type Params struct {
	UserRepo  domain.UserRepository
	TokenRepo domain.TokenRepository
	AuditRepo domain.AuditLogRepository
	JWT       jwt.Manager
}

type Payload struct {
	RefreshToken string
}

type Result struct {
	Tokens *domain.TokenPair
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
	refreshToken, err := u.TokenRepo.GetRefreshToken(u.RefreshToken)
	if err != nil {
		logger.Debug().Msg("refresh token not found")
		return nil, ErrInvalidToken
	}

	if time.Now().After(refreshToken.ExpiresAt) {
		_ = u.TokenRepo.DeleteRefreshToken(u.RefreshToken)
		logger.Debug().Msg("refresh token expired")
		return nil, ErrInvalidToken
	}

	user, err := u.UserRepo.GetByID(refreshToken.UserID)
	if err != nil {
		logger.Error().Err(err).Str("user_id", refreshToken.UserID.String()).Msg("user not found for refresh token")
		return nil, err
	}

	if err := u.TokenRepo.DeleteRefreshToken(u.RefreshToken); err != nil {
		logger.Warn().Err(err).Msg("failed to delete old refresh token")
	}

	tokens, err := u.generateTokens(user)
	if err != nil {
		return nil, err
	}

	u.logAudit(&user.ID, domain.EventTokenRefreshed, nil)

	logger.Info().Str("user_id", user.ID.String()).Msg("tokens refreshed successfully")

	return &Result{Tokens: tokens}, nil
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

func (u *UseCase) generateTokens(user *domain.User) (*domain.TokenPair, error) {
	accessToken, err := u.JWT.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		logger.Error().Err(err).Msg("failed to generate access token")
		return nil, err
	}

	refreshToken, refreshExp, err := u.JWT.GenerateRefreshToken()
	if err != nil {
		logger.Error().Err(err).Msg("failed to generate refresh token")
		return nil, err
	}

	storedToken := &domain.RefreshToken{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: refreshExp,
	}

	if err := u.TokenRepo.StoreRefreshToken(storedToken); err != nil {
		logger.Error().Err(err).Msg("failed to store refresh token")
		return nil, err
	}

	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
