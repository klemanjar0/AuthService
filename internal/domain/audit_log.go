package domain

import (
	"time"

	"github.com/google/uuid"
)

const (
	EventUserRegistered   = "user.registered"
	EventUserLogin        = "user.login"
	EventUserLoginFailed  = "user.login_failed"
	EventUserLogout       = "user.logout"
	EventUserLogoutAll    = "user.logout_all"
	EventTokenRefreshed   = "token.refreshed"
	EventSessionRefreshed = "session.refreshed"
	EventSessionValidated = "session.validated"
)

type AuditLog struct {
	ID        uuid.UUID
	UserID    *uuid.UUID
	EventType string
	IP        string
	UA        string
	Payload   []byte
	CreatedAt time.Time
}

type AuditLogRepository interface {
	Create(log *AuditLog) error
	GetByUserID(userID uuid.UUID, limit, offset int32) ([]*AuditLog, error)
	DeleteOld() error
}
