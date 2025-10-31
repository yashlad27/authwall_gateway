package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/yashlad/authwall-gateway/internal/auth"
	"github.com/yashlad/authwall-gateway/internal/session"
)

type contextKey string

const (
	UserContextKey    contextKey = "user"
	SessionContextKey contextKey = "session"
)

// AuthMiddleware provides JWT authentication middleware
type AuthMiddleware struct {
	jwtManager     *auth.JWTManager
	sessionManager *session.SessionManager
}

// NewAuthMiddleware creates a new auth middleware
func NewAuthMiddleware(jwtManager *auth.JWTManager, sessionManager *session.SessionManager) *AuthMiddleware {
	return &AuthMiddleware{
		jwtManager:     jwtManager,
		sessionManager: sessionManager,
	}
}

// Authenticate middleware validates JWT tokens
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Check Bearer token format
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
			return
		}

		token := parts[1]

		// Validate token
		claims, err := m.jwtManager.ValidateToken(token)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Add claims to context
		ctx := context.WithValue(r.Context(), UserContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireSession middleware validates session
func (m *AuthMiddleware) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get session ID from cookie
		cookie, err := r.Cookie("session_id")
		if err != nil {
			http.Error(w, "Session required", http.StatusUnauthorized)
			return
		}

		// Retrieve session
		sess, err := m.sessionManager.GetSession(cookie.Value)
		if err != nil {
			http.Error(w, "Invalid or expired session", http.StatusUnauthorized)
			return
		}

		// Refresh session activity
		m.sessionManager.RefreshSession(sess.SessionID)

		// Add session to context
		ctx := context.WithValue(r.Context(), SessionContextKey, sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireMFA middleware ensures MFA verification
func (m *AuthMiddleware) RequireMFA(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := r.Context().Value(SessionContextKey).(*session.Session)
		if !ok {
			http.Error(w, "Session not found", http.StatusUnauthorized)
			return
		}

		if !sess.MFAVerified {
			http.Error(w, "MFA verification required", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// RequireRole middleware checks if user has required role
func (m *AuthMiddleware) RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := r.Context().Value(UserContextKey).(*auth.Claims)
			if !ok {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Check if user has any of the required roles
			hasRole := false
			for _, role := range roles {
				for _, userRole := range claims.Roles {
					if userRole == role {
						hasRole = true
						break
					}
				}
				if hasRole {
					break
				}
			}

			if !hasRole {
				http.Error(w, "Insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetUserFromContext retrieves user claims from context
func GetUserFromContext(ctx context.Context) (*auth.Claims, bool) {
	claims, ok := ctx.Value(UserContextKey).(*auth.Claims)
	return claims, ok
}

// GetSessionFromContext retrieves session from context
func GetSessionFromContext(ctx context.Context) (*session.Session, bool) {
	sess, ok := ctx.Value(SessionContextKey).(*session.Session)
	return sess, ok
}
