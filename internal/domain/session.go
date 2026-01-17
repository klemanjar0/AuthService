package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Session struct {
	ID        string    `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	UserAgent string    `json:"user_agent"`
	IP        string    `json:"ip"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

type SessionRepository interface {
	Create(ctx context.Context, session *Session) error
	Get(ctx context.Context, sessionID string) (*Session, error)
	Refresh(ctx context.Context, sessionID string, newExpiry time.Duration) (*Session, error)
	Delete(ctx context.Context, sessionID string) error
	DeleteAllUserSessions(ctx context.Context, userID uuid.UUID) error
}
