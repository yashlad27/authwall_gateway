package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/yashlad/authwall-gateway/internal/auth"
	"github.com/yashlad/authwall-gateway/internal/database"
	"github.com/yashlad/authwall-gateway/internal/middleware"
	"github.com/yashlad/authwall-gateway/internal/mfa"
	"github.com/yashlad/authwall-gateway/internal/session"
)

// AuthHandler handles authentication endpoints
type AuthHandler struct {
	userRepo       *database.UserRepository
	accessLogRepo  *database.AccessLogRepository
	jwtManager     *auth.JWTManager
	totpManager    *mfa.TOTPManager
	sessionManager *session.SessionManager
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(
	userRepo *database.UserRepository,
	accessLogRepo *database.AccessLogRepository,
	jwtManager *auth.JWTManager,
	totpManager *mfa.TOTPManager,
	sessionManager *session.SessionManager,
) *AuthHandler {
	return &AuthHandler{
		userRepo:       userRepo,
		accessLogRepo:  accessLogRepo,
		jwtManager:     jwtManager,
		totpManager:    totpManager,
		sessionManager: sessionManager,
	}
}

// LoginRequest represents a login request
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TOTPCode string `json:"totp_code,omitempty"`
}

// LoginResponse represents a login response
type LoginResponse struct {
	Token        string  `json:"token,omitempty"`
	SessionID    string  `json:"session_id,omitempty"`
	MFARequired  bool    `json:"mfa_required"`
	User         *UserInfo `json:"user,omitempty"`
	Message      string  `json:"message,omitempty"`
}

// UserInfo represents user information
type UserInfo struct {
	ID         uint     `json:"id"`
	Email      string   `json:"email"`
	FirstName  string   `json:"first_name"`
	LastName   string   `json:"last_name"`
	Roles      []string `json:"roles"`
	MFAEnabled bool     `json:"mfa_enabled"`
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Verify credentials
	user, err := h.userRepo.VerifyPassword(ctx, req.Email, req.Password)
	if err != nil {
		h.logAccess(ctx, 0, req.Email, "login", http.StatusUnauthorized)
		respondError(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Check if MFA is enabled
	if user.MFAEnabled {
		if req.TOTPCode == "" {
			respondJSON(w, http.StatusOK, LoginResponse{
				MFARequired: true,
				Message:     "MFA verification required",
			})
			return
		}

		// Verify TOTP code
		valid, err := h.totpManager.VerifyCode(user.MFASecret, req.TOTPCode)
		if err != nil || !valid {
			h.logAccess(ctx, user.ID, user.Email, "login", http.StatusUnauthorized)
			respondError(w, "Invalid MFA code", http.StatusUnauthorized)
			return
		}
	}

	// Get device info and risk score from context
	deviceInfo, _ := middleware.GetDeviceInfoFromContext(ctx)
	riskScore, _ := middleware.GetRiskScoreFromContext(ctx)

	// Generate JWT token
	roles := strings.Split(user.Roles, ",")
	token, err := h.jwtManager.GenerateToken(
		fmt.Sprintf("%d", user.ID),
		user.Email,
		roles,
		deviceInfo.DeviceID,
	)
	if err != nil {
		respondError(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Create session
	sessionID := uuid.New().String()
	sess := &session.Session{
		SessionID:    sessionID,
		UserID:       fmt.Sprintf("%d", user.ID),
		Email:        user.Email,
		DeviceID:     deviceInfo.DeviceID,
		IPAddress:    deviceInfo.IPAddress,
		UserAgent:    deviceInfo.UserAgent,
		MFAVerified:  user.MFAEnabled,
		RiskScore:    riskScore.Score,
	}

	if err := h.sessionManager.CreateSession(sess); err != nil {
		respondError(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600, // 1 hour
	})

	// Log successful login
	h.logAccess(ctx, user.ID, user.Email, "login", http.StatusOK)

	// Send response
	respondJSON(w, http.StatusOK, LoginResponse{
		Token:     token,
		SessionID: sessionID,
		MFARequired: false,
		User: &UserInfo{
			ID:         user.ID,
			Email:      user.Email,
			FirstName:  user.FirstName,
			LastName:   user.LastName,
			Roles:      roles,
			MFAEnabled: user.MFAEnabled,
		},
		Message: "Login successful",
	})
}

// Logout handles user logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get session from context
	sess, ok := middleware.GetSessionFromContext(ctx)
	if ok {
		h.sessionManager.DeleteSession(sess.SessionID)
	}

	// Revoke JWT token
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 {
			h.jwtManager.RevokeToken(parts[1])
		}
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		MaxAge:   -1,
	})

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "Logout successful",
	})
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		respondError(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 {
		respondError(w, "Invalid authorization header", http.StatusUnauthorized)
		return
	}

	newToken, err := h.jwtManager.RefreshToken(parts[1])
	if err != nil {
		respondError(w, "Failed to refresh token", http.StatusUnauthorized)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"token": newToken,
	})
}

// logAccess logs access attempts
func (h *AuthHandler) logAccess(ctx context.Context, userID uint, email, action string, statusCode int) {
	deviceInfo, _ := middleware.GetDeviceInfoFromContext(ctx)
	riskScore, _ := middleware.GetRiskScoreFromContext(ctx)

	log := &database.AccessLog{
		UserID:      userID,
		Email:       email,
		IPAddress:   deviceInfo.IPAddress,
		DeviceID:    deviceInfo.DeviceID,
		UserAgent:   deviceInfo.UserAgent,
		Action:      action,
		StatusCode:  statusCode,
		RiskScore:   riskScore.Score,
		RiskLevel:   riskScore.Level,
		MFAVerified: false,
		Timestamp:   time.Now(),
	}

	h.accessLogRepo.Create(log)
}

// Helper functions
func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, message string, status int) {
	respondJSON(w, status, map[string]string{"error": message})
}
