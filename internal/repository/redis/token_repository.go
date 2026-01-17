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
	ErrTokenNotFound = errors.New("refresh token not found")
)

type TokenRepository struct {
	client *redis.Client
}

func NewTokenRepository(client *redis.Client) *TokenRepository {
	return &TokenRepository{client: client}
}

func (r *TokenRepository) StoreRefreshToken(ctx context.Context, token *domain.RefreshToken) error {
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}

	ttl := time.Until(token.ExpiresAt)
	if ttl <= 0 {
		return errors.New("token already expired")
	}

	key := r.tokenKey(token.Token)
	if err := r.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return err
	}

	userKey := r.userTokensKey(token.UserID)
	return r.client.SAdd(ctx, userKey, token.Token).Err()
}

func (r *TokenRepository) GetRefreshToken(ctx context.Context, token string) (*domain.RefreshToken, error) {
	key := r.tokenKey(token)
	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrTokenNotFound
		}
		return nil, err
	}

	var refreshToken domain.RefreshToken
	if err := json.Unmarshal(data, &refreshToken); err != nil {
		return nil, err
	}

	return &refreshToken, nil
}

func (r *TokenRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	key := r.tokenKey(token)
	return r.client.Del(ctx, key).Err()
}

func (r *TokenRepository) DeleteAllUserTokens(ctx context.Context, userID uuid.UUID) error {
	userKey := r.userTokensKey(userID)
	tokens, err := r.client.SMembers(ctx, userKey).Result()
	if err != nil {
		return err
	}

	if len(tokens) > 0 {
		keys := make([]string, len(tokens))
		for i, token := range tokens {
			keys[i] = r.tokenKey(token)
		}
		if err := r.client.Del(ctx, keys...).Err(); err != nil {
			return err
		}
	}

	return r.client.Del(ctx, userKey).Err()
}

func (r *TokenRepository) tokenKey(token string) string {
	return "refresh_token:" + token
}

func (r *TokenRepository) userTokensKey(userID uuid.UUID) string {
	return "user_tokens:" + userID.String()
}
