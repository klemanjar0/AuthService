package auth

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/yourusername/authservice/internal/domain"
	"github.com/yourusername/authservice/internal/pkg/hasher"
	"github.com/yourusername/authservice/internal/pkg/jwt"
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidToken       = errors.New("invalid or expired token")
)

type authUseCase struct {
	userRepo    domain.UserRepository
	tokenRepo   domain.TokenRepository
	sessionRepo domain.SessionRepository
	hasher      hasher.Hasher
	jwt         jwt.Manager
	sessionExp  time.Duration
}

func NewAuthUseCase(
	userRepo domain.UserRepository,
	tokenRepo domain.TokenRepository,
	sessionRepo domain.SessionRepository,
	hasher hasher.Hasher,
	jwt jwt.Manager,
	sessionExp time.Duration,
) UseCase {
	return &authUseCase{
		userRepo:    userRepo,
		tokenRepo:   tokenRepo,
		sessionRepo: sessionRepo,
		hasher:      hasher,
		jwt:         jwt,
		sessionExp:  sessionExp,
	}
}

func (uc *authUseCase) Register(ctx context.Context, input RegisterInput) (*AuthResult, error) {
	existingUser, _ := uc.userRepo.GetByEmail(input.Email)
	if existingUser != nil {
		return nil, ErrUserAlreadyExists
	}

	passwordHash, err := uc.hasher.Hash(input.Password)
	if err != nil {
		return nil, err
	}

	user := &domain.User{
		ID:           uuid.New(),
		Email:        input.Email,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := uc.userRepo.Create(user); err != nil {
		return nil, err
	}

	tokens, err := uc.generateTokens(user)
	if err != nil {
		return nil, err
	}

	return &AuthResult{
		User:   user,
		Tokens: tokens,
	}, nil
}

func (uc *authUseCase) Login(ctx context.Context, input LoginInput) (*AuthResult, error) {
	user, err := uc.userRepo.GetByEmail(input.Email)
	if err != nil {
		return nil, ErrInvalidCredentials
	}

	if !uc.hasher.Compare(user.PasswordHash, input.Password) {
		return nil, ErrInvalidCredentials
	}

	tokens, err := uc.generateTokens(user)
	if err != nil {
		return nil, err
	}

	session := &domain.Session{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		UserAgent: input.UserAgent,
		IP:        input.IP,
		ExpiresAt: time.Now().Add(uc.sessionExp),
		CreatedAt: time.Now(),
	}

	if err := uc.sessionRepo.Create(session); err != nil {
		return nil, err
	}

	return &AuthResult{
		User:      user,
		Tokens:    tokens,
		SessionID: session.ID,
	}, nil
}

func (uc *authUseCase) Refresh(ctx context.Context, input RefreshInput) (*domain.TokenPair, error) {
	refreshToken, err := uc.tokenRepo.GetRefreshToken(input.RefreshToken)
	if err != nil {
		return nil, ErrInvalidToken
	}

	if time.Now().After(refreshToken.ExpiresAt) {
		_ = uc.tokenRepo.DeleteRefreshToken(input.RefreshToken)
		return nil, ErrInvalidToken
	}

	user, err := uc.userRepo.GetByID(refreshToken.UserID)
	if err != nil {
		return nil, err
	}

	if err := uc.tokenRepo.DeleteRefreshToken(input.RefreshToken); err != nil {
		return nil, err
	}

	return uc.generateTokens(user)
}

func (uc *authUseCase) Logout(ctx context.Context, userID uuid.UUID, sessionID string) error {
	if sessionID != "" {
		if err := uc.sessionRepo.Delete(sessionID); err != nil {
			return err
		}
	}
	return nil
}

func (uc *authUseCase) LogoutAll(ctx context.Context, userID uuid.UUID) error {
	if err := uc.tokenRepo.DeleteAllUserTokens(userID); err != nil {
		return err
	}
	return uc.sessionRepo.DeleteAllUserSessions(userID)
}

func (uc *authUseCase) ValidateSession(ctx context.Context, sessionID string) (*domain.Session, error) {
	session, err := uc.sessionRepo.Get(sessionID)
	if err != nil {
		return nil, err
	}

	if time.Now().After(session.ExpiresAt) {
		_ = uc.sessionRepo.Delete(sessionID)
		return nil, errors.New("session expired")
	}

	return session, nil
}

func (uc *authUseCase) generateTokens(user *domain.User) (*domain.TokenPair, error) {
	accessToken, err := uc.jwt.GenerateAccessToken(user.ID, user.Email)
	if err != nil {
		return nil, err
	}

	refreshToken, refreshExp, err := uc.jwt.GenerateRefreshToken()
	if err != nil {
		return nil, err
	}

	storedToken := &domain.RefreshToken{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: refreshExp,
	}

	if err := uc.tokenRepo.StoreRefreshToken(storedToken); err != nil {
		return nil, err
	}

	return &domain.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}
