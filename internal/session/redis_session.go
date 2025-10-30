package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
)

// Session represents a user session
type Session struct {
	SessionID    string            `json:"session_id"`
	UserID       string            `json:"user_id"`
	Email        string            `json:"email"`
	DeviceID     string            `json:"device_id"`
	IPAddress    string            `json:"ip_address"`
	UserAgent    string            `json:"user_agent"`
	MFAVerified  bool              `json:"mfa_verified"`
	RiskScore    float64           `json:"risk_score"`
	CreatedAt    time.Time         `json:"created_at"`
	LastActivity time.Time         `json:"last_activity"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// SessionManager manages user sessions
type SessionManager struct {
	client         *redis.Client
	prefix         string
	sessionTimeout time.Duration
}

// NewSessionManager creates a new session manager
func NewSessionManager(redisURL, prefix string, sessionTimeout time.Duration) (*SessionManager, error) {
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

	return &SessionManager{
		client:         client,
		prefix:         prefix,
		sessionTimeout: sessionTimeout,
	}, nil
}

// CreateSession creates a new session
func (sm *SessionManager) CreateSession(session *Session) error {
	ctx := context.Background()

	session.CreatedAt = time.Now()
	session.LastActivity = time.Now()

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	key := sm.getKey(session.SessionID)
	return sm.client.Set(ctx, key, data, sm.sessionTimeout).Err()
}

// GetSession retrieves a session by ID
func (sm *SessionManager) GetSession(sessionID string) (*Session, error) {
	ctx := context.Background()
	key := sm.getKey(sessionID)

	data, err := sm.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}

	var session Session
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	return &session, nil
}

// UpdateSession updates an existing session
func (sm *SessionManager) UpdateSession(session *Session) error {
	ctx := context.Background()

	session.LastActivity = time.Now()

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}

	key := sm.getKey(session.SessionID)
	
	// Get remaining TTL
	ttl, err := sm.client.TTL(ctx, key).Result()
	if err != nil {
		return err
	}

	// If session exists, preserve TTL; otherwise use default timeout
	if ttl < 0 {
		ttl = sm.sessionTimeout
	}

	return sm.client.Set(ctx, key, data, ttl).Err()
}

// DeleteSession deletes a session
func (sm *SessionManager) DeleteSession(sessionID string) error {
	ctx := context.Background()
	key := sm.getKey(sessionID)
	return sm.client.Del(ctx, key).Err()
}

// RefreshSession extends the session timeout
func (sm *SessionManager) RefreshSession(sessionID string) error {
	ctx := context.Background()
	key := sm.getKey(sessionID)

	return sm.client.Expire(ctx, key, sm.sessionTimeout).Err()
}

// GetUserSessions gets all sessions for a user
func (sm *SessionManager) GetUserSessions(userID string) ([]*Session, error) {
	ctx := context.Background()
	pattern := sm.getUserSessionPattern()

	var sessions []*Session
	iter := sm.client.Scan(ctx, 0, pattern, 0).Iterator()
	
	for iter.Next(ctx) {
		data, err := sm.client.Get(ctx, iter.Val()).Result()
		if err != nil {
			continue
		}

		var session Session
		if err := json.Unmarshal([]byte(data), &session); err != nil {
			continue
		}

		if session.UserID == userID {
			sessions = append(sessions, &session)
		}
	}

	if err := iter.Err(); err != nil {
		return nil, err
	}

	return sessions, nil
}

// DeleteUserSessions deletes all sessions for a user
func (sm *SessionManager) DeleteUserSessions(userID string) error {
	sessions, err := sm.GetUserSessions(userID)
	if err != nil {
		return err
	}

	ctx := context.Background()
	for _, session := range sessions {
		key := sm.getKey(session.SessionID)
		if err := sm.client.Del(ctx, key).Err(); err != nil {
			return err
		}
	}

	return nil
}

// getKey generates the Redis key for a session
func (sm *SessionManager) getKey(sessionID string) string {
	return fmt.Sprintf("%s:session:%s", sm.prefix, sessionID)
}

// getUserSessionPattern generates the pattern for user sessions
func (sm *SessionManager) getUserSessionPattern() string {
	return fmt.Sprintf("%s:session:*", sm.prefix)
}

// Close closes the Redis connection
func (sm *SessionManager) Close() error {
	return sm.client.Close()
}
