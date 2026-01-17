package register

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/yourusername/authservice/internal/domain"
	"github.com/yourusername/authservice/internal/pkg/hasher"
	"github.com/yourusername/authservice/internal/pkg/jwt"
	"github.com/yourusername/authservice/internal/pkg/logger"
)

var (
	ErrUserAlreadyExists = errors.New("user already exists")
)

type Params struct {
	UserRepo  domain.UserRepository
	TokenRepo domain.TokenRepository
	AuditRepo domain.AuditLogRepository
	Hasher    hasher.Hasher
	JWT       jwt.Manager
}

type Payload struct {
	Email    string
	Password string
}

type Result struct {
	User   *domain.User
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
	existingUser, _ := u.UserRepo.GetByEmail(u.Email)
	if existingUser != nil {
		return nil, ErrUserAlreadyExists
	}

	passwordHash, err := u.Hasher.Hash(u.Password)
	if err != nil {
		logger.Error().Err(err).Msg("failed to hash password")
		return nil, err
	}

	user := &domain.User{
		ID:           uuid.New(),
		Email:        u.Email,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := u.UserRepo.Create(user); err != nil {
		logger.Error().Err(err).Str("email", u.Email).Msg("failed to create user")
		return nil, err
	}

	tokens, err := u.generateTokens(user)
	if err != nil {
		return nil, err
	}

	u.logAudit(&user.ID, domain.EventUserRegistered, map[string]any{"email": user.Email})

	logger.Info().Str("user_id", user.ID.String()).Str("email", user.Email).Msg("user registered successfully")

	return &Result{
		User:   user,
		Tokens: tokens,
	}, nil
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
