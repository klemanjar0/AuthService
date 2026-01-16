package login

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/yourusername/authservice/internal/domain"
	"github.com/yourusername/authservice/internal/pkg/hasher"
	"github.com/yourusername/authservice/internal/pkg/jwt"
	"github.com/yourusername/authservice/internal/pkg/logger"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
)

type Params struct {
	UserRepo    domain.UserRepository
	TokenRepo   domain.TokenRepository
	SessionRepo domain.SessionRepository
	Hasher      hasher.Hasher
	JWT         jwt.Manager
	SessionExp  time.Duration
}

type Payload struct {
	Email     string
	Password  string
	UserAgent string
	IP        string
}

type Result struct {
	User      *domain.User
	Tokens    *domain.TokenPair
	SessionID string
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
	user, err := u.UserRepo.GetByEmail(u.Email)
	if err != nil {
		logger.Debug().Str("email", u.Email).Msg("user not found")
		return nil, ErrInvalidCredentials
	}

	if !u.Hasher.Compare(user.PasswordHash, u.Password) {
		logger.Debug().Str("email", u.Email).Msg("invalid password")
		return nil, ErrInvalidCredentials
	}

	tokens, err := u.generateTokens(user)
	if err != nil {
		return nil, err
	}

	session := &domain.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		UserAgent: u.UserAgent,
		IP:        u.IP,
		ExpiresAt: time.Now().Add(u.SessionExp),
		CreatedAt: time.Now(),
	}

	if err := u.SessionRepo.Create(session); err != nil {
		logger.Error().Err(err).Str("user_id", user.ID.String()).Msg("failed to create session")
		return nil, err
	}

	logger.Info().
		Str("user_id", user.ID.String()).
		Str("session_id", session.ID).
		Msg("user logged in successfully")

	return &Result{
		User:      user,
		Tokens:    tokens,
		SessionID: session.ID,
	}, nil
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
