package middleware

import (
	"context"
	"net/http"

	"github.com/yashlad/authwall-gateway/internal/risk"
)

type riskContextKey string

const (
	RiskScoreContextKey riskContextKey = "risk_score"
	DeviceInfoContextKey riskContextKey = "device_info"
)

// RiskMiddleware provides risk assessment middleware
type RiskMiddleware struct {
	analyzer *risk.RiskAnalyzer
}

// NewRiskMiddleware creates a new risk middleware
func NewRiskMiddleware(analyzer *risk.RiskAnalyzer) *RiskMiddleware {
	return &RiskMiddleware{
		analyzer: analyzer,
	}
}

// AssessRisk middleware calculates risk score for each request
func (rm *RiskMiddleware) AssessRisk(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract device information
		deviceInfo := &risk.DeviceInfo{
			IPAddress: getClientIP(r),
			UserAgent: r.Header.Get("User-Agent"),
		}

		// Generate device fingerprint
		deviceInfo.Fingerprint = risk.GenerateDeviceFingerprint(
			deviceInfo.UserAgent,
			deviceInfo.IPAddress,
			nil,
		)
		deviceInfo.DeviceID = deviceInfo.Fingerprint

		// Calculate risk score
		riskScore := rm.analyzer.CalculateRiskScore(deviceInfo)

		// Block if risk is too high
		if riskScore.Blocked {
			w.Header().Set("X-Risk-Score", formatFloat(riskScore.Score))
			w.Header().Set("X-Risk-Level", riskScore.Level)
			http.Error(w, "Access denied: "+riskScore.Reason, http.StatusForbidden)
			return
		}

		// Add risk score and device info to context
		ctx := r.Context()
		ctx = context.WithValue(ctx, RiskScoreContextKey, riskScore)
		ctx = context.WithValue(ctx, DeviceInfoContextKey, deviceInfo)

		// Add risk headers
		w.Header().Set("X-Risk-Score", formatFloat(riskScore.Score))
		w.Header().Set("X-Risk-Level", riskScore.Level)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetRiskScoreFromContext retrieves risk score from context
func GetRiskScoreFromContext(ctx context.Context) (*risk.RiskScore, bool) {
	score, ok := ctx.Value(RiskScoreContextKey).(*risk.RiskScore)
	return score, ok
}

// GetDeviceInfoFromContext retrieves device info from context
func GetDeviceInfoFromContext(ctx context.Context) (*risk.DeviceInfo, bool) {
	info, ok := ctx.Value(DeviceInfoContextKey).(*risk.DeviceInfo)
	return info, ok
}

// formatFloat formats a float64 to string with 2 decimal places
func formatFloat(f float64) string {
	return string(rune(int(f*100)/100))
}
