package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisRevokeStore implements RevokeStore using Redis
type RedisRevokeStore struct {
	client *redis.Client
	prefix string
}

// NewRedisRevokeStore creates a new Redis-based revoke store
func NewRedisRevokeStore(redisURL, prefix string) (*RedisRevokeStore, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	return &RedisRevokeStore{
		client: client,
		prefix: prefix,
	}, nil
}

// IsRevoked checks if a token is revoked
func (r *RedisRevokeStore) IsRevoked(tokenID string) (bool, error) {
	ctx := context.Background()
	key := r.getKey(tokenID)

	val, err := r.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	return val == "revoked", nil
}

// RevokeToken revokes a token
func (r *RedisRevokeStore) RevokeToken(tokenID string, expiry time.Duration) error {
	ctx := context.Background()
	key := r.getKey(tokenID)

	return r.client.Set(ctx, key, "revoked", expiry).Err()
}

// getKey generates the Redis key for a token
func (r *RedisRevokeStore) getKey(tokenID string) string {
	return fmt.Sprintf("%s:revoked:%s", r.prefix, tokenID)
}

// Close closes the Redis connection
func (r *RedisRevokeStore) Close() error {
	return r.client.Close()
}
