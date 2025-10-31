package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/yashlad/authwall-gateway/internal/database"
	"github.com/yashlad/authwall-gateway/internal/mfa"
	"github.com/yashlad/authwall-gateway/internal/middleware"
)

// MFAHandler handles MFA-related endpoints
type MFAHandler struct {
	userRepo    *database.UserRepository
	totpManager *mfa.TOTPManager
}

// NewMFAHandler creates a new MFA handler
func NewMFAHandler(userRepo *database.UserRepository, totpManager *mfa.TOTPManager) *MFAHandler {
	return &MFAHandler{
		userRepo:    userRepo,
		totpManager: totpManager,
	}
}

// SetupMFAResponse represents MFA setup response
type SetupMFAResponse struct {
	Secret        string   `json:"secret"`
	QRCodeURL     string   `json:"qr_code_url"`
	RecoveryCodes []string `json:"recovery_codes"`
}

// VerifyMFARequest represents MFA verification request
type VerifyMFARequest struct {
	Code string `json:"code"`
}

// SetupMFA initiates MFA setup for a user
func (h *MFAHandler) SetupMFA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		respondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get user from database
	user, err := h.userRepo.GetByEmail(ctx, claims.Email)
	if err != nil {
		respondError(w, "User not found", http.StatusNotFound)
		return
	}

	// Generate TOTP secret
	totpSecret, err := h.totpManager.GenerateSecret(user.Email)
	if err != nil {
		respondError(w, "Failed to generate MFA secret", http.StatusInternalServerError)
		return
	}

	// Generate recovery codes
	recoveryCodes, err := mfa.GenerateRecoveryCodes(8)
	if err != nil {
		respondError(w, "Failed to generate recovery codes", http.StatusInternalServerError)
		return
	}

	// Store in database (but don't enable yet - requires verification)
	recoveryJSON, _ := json.Marshal(recoveryCodes)
	user.MFASecret = totpSecret.Secret
	user.RecoveryCodes = string(recoveryJSON)
	
	if err := h.userRepo.Update(ctx, user); err != nil {
		respondError(w, "Failed to save MFA settings", http.StatusInternalServerError)
		return
	}

	respondJSON(w, http.StatusOK, SetupMFAResponse{
		Secret:        totpSecret.Secret,
		QRCodeURL:     totpSecret.URL,
		RecoveryCodes: recoveryCodes,
	})
}

// VerifyAndEnableMFA verifies TOTP code and enables MFA
func (h *MFAHandler) VerifyAndEnableMFA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		respondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req VerifyMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get user from database
	user, err := h.userRepo.GetByEmail(ctx, claims.Email)
	if err != nil {
		respondError(w, "User not found", http.StatusNotFound)
		return
	}

	// Verify TOTP code
	valid, err := h.totpManager.VerifyCode(user.MFASecret, req.Code)
	if err != nil || !valid {
		respondError(w, "Invalid verification code", http.StatusBadRequest)
		return
	}

	// Enable MFA
	if err := h.userRepo.EnableMFA(ctx, user.ID, user.MFASecret, user.RecoveryCodes); err != nil {
		respondError(w, "Failed to enable MFA", http.StatusInternalServerError)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "MFA enabled successfully",
	})
}

// DisableMFA disables MFA for a user
func (h *MFAHandler) DisableMFA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		respondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req VerifyMFARequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get user from database
	user, err := h.userRepo.GetByEmail(ctx, claims.Email)
	if err != nil {
		respondError(w, "User not found", http.StatusNotFound)
		return
	}

	// Verify current TOTP code before disabling
	valid, err := h.totpManager.VerifyCode(user.MFASecret, req.Code)
	if err != nil || !valid {
		respondError(w, "Invalid verification code", http.StatusBadRequest)
		return
	}

	// Disable MFA
	if err := h.userRepo.DisableMFA(ctx, user.ID); err != nil {
		respondError(w, "Failed to disable MFA", http.StatusInternalServerError)
		return
	}

	respondJSON(w, http.StatusOK, map[string]string{
		"message": "MFA disabled successfully",
	})
}
