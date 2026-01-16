package jwt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/yourusername/authservice/internal/domain"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token has expired")
)

type Manager interface {
	GenerateAccessToken(userID uuid.UUID, email string) (string, error)
	GenerateRefreshToken() (string, time.Time, error)
	ValidateAccessToken(tokenString string) (*domain.AccessTokenClaims, error)
}

type jwtManager struct {
	secret        []byte
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

func NewManager(secret string, accessExpiry, refreshExpiry time.Duration) Manager {
	return &jwtManager{
		secret:        []byte(secret),
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
	}
}

func (m *jwtManager) GenerateAccessToken(userID uuid.UUID, email string) (string, error) {
	now := time.Now()

	claims := domain.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(m.accessExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "authservice",
			Subject:   userID.String(),
		},
		UserID: userID,
		Email:  email,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secret)
}

func (m *jwtManager) GenerateRefreshToken() (string, time.Time, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", time.Time{}, err
	}

	token := base64.URLEncoding.EncodeToString(bytes)
	expiresAt := time.Now().Add(m.refreshExpiry)

	return token, expiresAt, nil
}

func (m *jwtManager) ValidateAccessToken(tokenString string) (*domain.AccessTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &domain.AccessTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return m.secret, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*domain.AccessTokenClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}
