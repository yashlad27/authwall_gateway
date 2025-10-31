package database

import (
	"context"
	"errors"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
)

// User represents a user in the system
type User struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	Email           string    `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash    string    `gorm:"not null" json:"-"`
	FirstName       string    `gorm:"not null" json:"first_name"`
	LastName        string    `gorm:"not null" json:"last_name"`
	Roles           string    `gorm:"not null;default:'user'" json:"roles"`
	MFAEnabled      bool      `gorm:"default:false" json:"mfa_enabled"`
	MFASecret       string    `json:"-"`
	RecoveryCodes   string    `json:"-"` // JSON-encoded array
	Active          bool      `gorm:"default:true" json:"active"`
	FailedAttempts  int       `gorm:"default:0" json:"-"`
	LockedUntil     *time.Time `json:"locked_until,omitempty"`
	LastLogin       *time.Time `json:"last_login,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// UserRepository handles database operations for users
type UserRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create creates a new user
func (r *UserRepository) Create(ctx context.Context, user *User) error {
	// Check if user already exists
	var existing User
	err := r.db.WithContext(ctx).Where("email = ?", user.Email).First(&existing).Error
	if err == nil {
		return ErrUserAlreadyExists
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.PasswordHash), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user.PasswordHash = string(hashedPassword)

	return r.db.WithContext(ctx).Create(user).Error
}

// GetByEmail retrieves a user by email
func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*User, error) {
	var user User
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	return &user, err
}

// GetByID retrieves a user by ID
func (r *UserRepository) GetByID(ctx context.Context, id uint) (*User, error) {
	var user User
	err := r.db.WithContext(ctx).First(&user, id).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrUserNotFound
	}
	return &user, err
}

// Update updates a user
func (r *UserRepository) Update(ctx context.Context, user *User) error {
	return r.db.WithContext(ctx).Save(user).Error
}

// Delete deletes a user
func (r *UserRepository) Delete(ctx context.Context, id uint) error {
	return r.db.WithContext(ctx).Delete(&User{}, id).Error
}

// VerifyPassword verifies a user's password
func (r *UserRepository) VerifyPassword(ctx context.Context, email, password string) (*User, error) {
	user, err := r.GetByEmail(ctx, email)
	if err != nil {
		return nil, err
	}

	// Check if account is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, errors.New("account is locked")
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		// Increment failed attempts
		user.FailedAttempts++
		if user.FailedAttempts >= 5 {
			lockUntil := time.Now().Add(15 * time.Minute)
			user.LockedUntil = &lockUntil
		}
		r.Update(ctx, user)
		return nil, ErrInvalidCredentials
	}

	// Reset failed attempts on successful login
	user.FailedAttempts = 0
	user.LockedUntil = nil
	now := time.Now()
	user.LastLogin = &now
	r.Update(ctx, user)

	return user, nil
}

// EnableMFA enables MFA for a user
func (r *UserRepository) EnableMFA(ctx context.Context, userID uint, secret, recoveryCodes string) error {
	return r.db.WithContext(ctx).Model(&User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"mfa_enabled":   true,
			"mfa_secret":    secret,
			"recovery_codes": recoveryCodes,
		}).Error
}

// DisableMFA disables MFA for a user
func (r *UserRepository) DisableMFA(ctx context.Context, userID uint) error {
	return r.db.WithContext(ctx).Model(&User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"mfa_enabled":   false,
			"mfa_secret":    "",
			"recovery_codes": "",
		}).Error
}

// ListUsers lists all users with pagination
func (r *UserRepository) ListUsers(ctx context.Context, limit, offset int) ([]User, int64, error) {
	var users []User
	var total int64

	if err := r.db.WithContext(ctx).Model(&User{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	err := r.db.WithContext(ctx).Limit(limit).Offset(offset).Find(&users).Error
	return users, total, err
}
