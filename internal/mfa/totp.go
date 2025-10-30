package mfa

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var (
	ErrInvalidCode   = errors.New("invalid verification code")
	ErrExpiredCode   = errors.New("verification code expired")
	ErrInvalidSecret = errors.New("invalid secret key")
)

// TOTPManager handles TOTP operations
type TOTPManager struct {
	issuer string
	period uint
	digits otp.Digits
}

// NewTOTPManager creates a new TOTP manager
func NewTOTPManager(issuer string) *TOTPManager {
	return &TOTPManager{
		issuer: issuer,
		period: 30, // 30 seconds
		digits: otp.DigitsSix,
	}
}

// GenerateSecret generates a new TOTP secret for a user
func (m *TOTPManager) GenerateSecret(accountName string) (*TOTPSecret, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      m.issuer,
		AccountName: accountName,
		Period:      m.period,
		Digits:      m.digits,
	})
	if err != nil {
		return nil, err
	}

	return &TOTPSecret{
		Secret: key.Secret(),
		URL:    key.URL(),
		QRCode: key.URL(), // This can be used to generate QR code on frontend
	}, nil
}

// VerifyCode verifies a TOTP code
func (m *TOTPManager) VerifyCode(secret, code string) (bool, error) {
	if secret == "" {
		return false, ErrInvalidSecret
	}

	valid := totp.Validate(code, secret)
	if !valid {
		return false, ErrInvalidCode
	}

	return true, nil
}

// VerifyCodeWithWindow verifies a TOTP code with a time window
func (m *TOTPManager) VerifyCodeWithWindow(secret, code string, window int) (bool, error) {
	if secret == "" {
		return false, ErrInvalidSecret
	}

	// Try current time and adjacent windows
	now := time.Now()
	for i := -window; i <= window; i++ {
		timestamp := now.Add(time.Duration(i) * time.Duration(m.period) * time.Second)
		expectedCode, err := totp.GenerateCode(secret, timestamp)
		if err != nil {
			return false, err
		}

		if code == expectedCode {
			return true, nil
		}
	}

	return false, ErrInvalidCode
}

// GetCurrentCode generates the current TOTP code (for testing)
func (m *TOTPManager) GetCurrentCode(secret string) (string, error) {
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		return "", err
	}
	return code, nil
}

// TOTPSecret contains TOTP setup information
type TOTPSecret struct {
	Secret string `json:"secret"`
	URL    string `json:"url"`
	QRCode string `json:"qr_code"`
}

// GenerateRecoveryCodes generates backup recovery codes
func GenerateRecoveryCodes(count int) ([]string, error) {
	codes := make([]string, count)
	for i := 0; i < count; i++ {
		code, err := generateRecoveryCode()
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}
	return codes, nil
}

// generateRecoveryCode generates a single recovery code
func generateRecoveryCode() (string, error) {
	bytes := make([]byte, 10)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Encode to base32 and format
	encoded := base32.StdEncoding.EncodeToString(bytes)
	return fmt.Sprintf("%s-%s", encoded[:5], encoded[5:10]), nil
}
