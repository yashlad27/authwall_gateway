package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/yashlad/authwall-gateway/internal/database"
	"github.com/yashlad/authwall-gateway/internal/middleware"
)

// UserHandler handles user-related endpoints
type UserHandler struct {
	userRepo *database.UserRepository
}

// NewUserHandler creates a new user handler
func NewUserHandler(userRepo *database.UserRepository) *UserHandler {
	return &UserHandler{
		userRepo: userRepo,
	}
}

// RegisterRequest represents a user registration request
type RegisterRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

// Register handles user registration
func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate input
	if req.Email == "" || req.Password == "" || req.FirstName == "" || req.LastName == "" {
		respondError(w, "All fields are required", http.StatusBadRequest)
		return
	}

	// Create user
	user := &database.User{
		Email:        req.Email,
		PasswordHash: req.Password, // Will be hashed in Create method
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Roles:        "user",
		Active:       true,
	}

	ctx := r.Context()
	if err := h.userRepo.Create(ctx, user); err != nil {
		if err == database.ErrUserAlreadyExists {
			respondError(w, "User already exists", http.StatusConflict)
			return
		}
		respondError(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"message": "User created successfully",
		"user": map[string]interface{}{
			"id":         user.ID,
			"email":      user.Email,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
		},
	})
}

// GetProfile returns the current user's profile
func (h *UserHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		respondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := h.userRepo.GetByEmail(ctx, claims.Email)
	if err != nil {
		respondError(w, "User not found", http.StatusNotFound)
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"id":          user.ID,
		"email":       user.Email,
		"first_name":  user.FirstName,
		"last_name":   user.LastName,
		"roles":       user.Roles,
		"mfa_enabled": user.MFAEnabled,
		"active":      user.Active,
		"created_at":  user.CreatedAt,
	})
}
