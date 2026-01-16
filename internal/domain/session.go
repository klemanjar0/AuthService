package domain

import (
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
	Create(session *Session) error
	Get(sessionID string) (*Session, error)
	Delete(sessionID string) error
	DeleteAllUserSessions(userID uuid.UUID) error
}
