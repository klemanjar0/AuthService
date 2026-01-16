package redis

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"

	"github.com/yourusername/authservice/internal/domain"
)

var (
	ErrSessionNotFound = errors.New("session not found")
)

type SessionRepository struct {
	client *redis.Client
}

func NewSessionRepository(client *redis.Client) *SessionRepository {
	return &SessionRepository{client: client}
}

func (r *SessionRepository) Create(session *domain.Session) error {
	ctx := context.Background()

	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	ttl := time.Until(session.ExpiresAt)
	if ttl <= 0 {
		return errors.New("session already expired")
	}

	key := r.sessionKey(session.ID)
	if err := r.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return err
	}

	userKey := r.userSessionsKey(session.UserID)
	return r.client.SAdd(ctx, userKey, session.ID).Err()
}

func (r *SessionRepository) Get(sessionID string) (*domain.Session, error) {
	ctx := context.Background()

	key := r.sessionKey(sessionID)
	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	var session domain.Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

func (r *SessionRepository) Delete(sessionID string) error {
	ctx := context.Background()
	key := r.sessionKey(sessionID)
	return r.client.Del(ctx, key).Err()
}

func (r *SessionRepository) DeleteAllUserSessions(userID uuid.UUID) error {
	ctx := context.Background()

	userKey := r.userSessionsKey(userID)
	sessions, err := r.client.SMembers(ctx, userKey).Result()
	if err != nil {
		return err
	}

	if len(sessions) > 0 {
		keys := make([]string, len(sessions))
		for i, sessionID := range sessions {
			keys[i] = r.sessionKey(sessionID)
		}
		if err := r.client.Del(ctx, keys...).Err(); err != nil {
			return err
		}
	}

	return r.client.Del(ctx, userKey).Err()
}

func (r *SessionRepository) sessionKey(sessionID string) string {
	return "session:" + sessionID
}

func (r *SessionRepository) userSessionsKey(userID uuid.UUID) string {
	return "user_sessions:" + userID.String()
}
