package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token expired")
	ErrTokenRevoked     = errors.New("token revoked")
	ErrInvalidSignature = errors.New("invalid signature")
)

// Claims represents JWT claims
type Claims struct {
	UserID   string   `json:"user_id"`
	Email    string   `json:"email"`
	Roles    []string `json:"roles"`
	DeviceID string   `json:"device_id"`
	jwt.RegisteredClaims
}

// JWTManager handles JWT token operations
type JWTManager struct {
	secretKey     []byte
	tokenDuration time.Duration
	revokeStore   RevokeStore
}

// RevokeStore interface for token revocation
type RevokeStore interface {
	IsRevoked(tokenID string) (bool, error)
	RevokeToken(tokenID string, expiry time.Duration) error
}

// NewJWTManager creates a new JWT manager
func NewJWTManager(secretKey string, tokenDuration time.Duration, revokeStore RevokeStore) *JWTManager {
	return &JWTManager{
		secretKey:     []byte(secretKey),
		tokenDuration: tokenDuration,
		revokeStore:   revokeStore,
	}
}

// GenerateToken creates a new JWT token
func (m *JWTManager) GenerateToken(userID, email string, roles []string, deviceID string) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID:   userID,
		Email:    email,
		Roles:    roles,
		DeviceID: deviceID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(m.tokenDuration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        generateTokenID(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(m.secretKey)
}

// ValidateToken validates and parses a JWT token
func (m *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidSignature
		}
		return m.secretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Check if token is revoked
	if m.revokeStore != nil {
		revoked, err := m.revokeStore.IsRevoked(claims.ID)
		if err != nil {
			return nil, err
		}
		if revoked {
			return nil, ErrTokenRevoked
		}
	}

	return claims, nil
}

// RevokeToken revokes a token by its ID
func (m *JWTManager) RevokeToken(tokenString string) error {
	claims, err := m.ValidateToken(tokenString)
	if err != nil && !errors.Is(err, ErrTokenExpired) {
		return err
	}

	// Calculate remaining time until expiration
	ttl := time.Until(claims.ExpiresAt.Time)
	if ttl < 0 {
		ttl = 0
	}

	return m.revokeStore.RevokeToken(claims.ID, ttl)
}

// RefreshToken creates a new token from an existing valid token
func (m *JWTManager) RefreshToken(tokenString string) (string, error) {
	claims, err := m.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	return m.GenerateToken(claims.UserID, claims.Email, claims.Roles, claims.DeviceID)
}

// generateTokenID generates a unique token ID
func generateTokenID() string {
	return time.Now().Format("20060102150405") + "-" + randomString(16)
}

// randomString generates a random string of given length
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}
