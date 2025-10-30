package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// DeviceInfo contains device fingerprint information
type DeviceInfo struct {
	DeviceID      string
	IPAddress     string
	UserAgent     string
	Fingerprint   string
	Location      string
	TrustedDevice bool
	LastSeen      time.Time
}

// RiskScore represents the calculated risk level
type RiskScore struct {
	Score       float64           `json:"score"`        // 0-100 (0=safe, 100=dangerous)
	Level       string            `json:"level"`        // low, medium, high, critical
	Factors     map[string]float64 `json:"factors"`      // Individual risk factors
	Timestamp   time.Time         `json:"timestamp"`
	DeviceID    string            `json:"device_id"`
	IPAddress   string            `json:"ip_address"`
	Blocked     bool              `json:"blocked"`
	Reason      string            `json:"reason,omitempty"`
}

// RiskAnalyzer analyzes and scores authentication attempts
type RiskAnalyzer struct {
	trustedIPs      map[string]bool
	blockedIPs      map[string]bool
	trustedDevices  map[string]*DeviceInfo
	ipReputationDB  IPReputationDB
}

// IPReputationDB interface for IP reputation lookup
type IPReputationDB interface {
	CheckReputation(ip string) (float64, error)
	IsBlacklisted(ip string) (bool, error)
}

// NewRiskAnalyzer creates a new risk analyzer
func NewRiskAnalyzer(ipReputationDB IPReputationDB) *RiskAnalyzer {
	return &RiskAnalyzer{
		trustedIPs:      make(map[string]bool),
		blockedIPs:      make(map[string]bool),
		trustedDevices:  make(map[string]*DeviceInfo),
		ipReputationDB:  ipReputationDB,
	}
}

// CalculateRiskScore calculates the risk score for an authentication attempt
func (ra *RiskAnalyzer) CalculateRiskScore(deviceInfo *DeviceInfo) *RiskScore {
	factors := make(map[string]float64)
	totalScore := 0.0

	// Factor 1: IP Reputation (0-30 points)
	ipScore := ra.calculateIPRisk(deviceInfo.IPAddress)
	factors["ip_reputation"] = ipScore
	totalScore += ipScore

	// Factor 2: Device Trust (0-25 points)
	deviceScore := ra.calculateDeviceTrust(deviceInfo)
	factors["device_trust"] = deviceScore
	totalScore += deviceScore

	// Factor 3: Location Analysis (0-15 points)
	locationScore := ra.calculateLocationRisk(deviceInfo)
	factors["location"] = locationScore
	totalScore += locationScore

	// Factor 4: Time-based Analysis (0-15 points)
	timeScore := ra.calculateTimeRisk(deviceInfo)
	factors["time_pattern"] = timeScore
	totalScore += timeScore

	// Factor 5: User Agent Analysis (0-15 points)
	uaScore := ra.calculateUserAgentRisk(deviceInfo.UserAgent)
	factors["user_agent"] = uaScore
	totalScore += uaScore

	// Determine risk level
	level := ra.getRiskLevel(totalScore)
	blocked := totalScore >= 70 // Block if score >= 70

	return &RiskScore{
		Score:     totalScore,
		Level:     level,
		Factors:   factors,
		Timestamp: time.Now(),
		DeviceID:  deviceInfo.DeviceID,
		IPAddress: deviceInfo.IPAddress,
		Blocked:   blocked,
		Reason:    ra.getBlockReason(factors, totalScore),
	}
}

// calculateIPRisk calculates risk based on IP address
func (ra *RiskAnalyzer) calculateIPRisk(ip string) float64 {
	// Check if IP is blocked
	if ra.blockedIPs[ip] {
		return 30.0
	}

	// Check if IP is trusted
	if ra.trustedIPs[ip] {
		return 0.0
	}

	// Check IP reputation from database
	if ra.ipReputationDB != nil {
		if blacklisted, _ := ra.ipReputationDB.IsBlacklisted(ip); blacklisted {
			ra.blockedIPs[ip] = true
			return 30.0
		}

		if score, err := ra.ipReputationDB.CheckReputation(ip); err == nil {
			return score * 30.0 / 100.0
		}
	}

	// Check if IP is from a private network
	if isPrivateIP(ip) {
		return 5.0 // Lower risk for private IPs
	}

	// Default: medium-low risk
	return 10.0
}

// calculateDeviceTrust calculates risk based on device trust
func (ra *RiskAnalyzer) calculateDeviceTrust(deviceInfo *DeviceInfo) float64 {
	device, exists := ra.trustedDevices[deviceInfo.DeviceID]
	
	if !exists {
		// New device - higher risk
		return 20.0
	}

	if device.TrustedDevice {
		// Trusted device - low risk
		return 0.0
	}

	// Device seen before but not trusted
	timeSinceLastSeen := time.Since(device.LastSeen)
	
	if timeSinceLastSeen < 24*time.Hour {
		return 5.0
	} else if timeSinceLastSeen < 7*24*time.Hour {
		return 10.0
	} else {
		return 15.0
	}
}

// calculateLocationRisk calculates risk based on location changes
func (ra *RiskAnalyzer) calculateLocationRisk(deviceInfo *DeviceInfo) float64 {
	device, exists := ra.trustedDevices[deviceInfo.DeviceID]
	
	if !exists {
		return 10.0 // Unknown location
	}

	// Check for location changes
	if device.Location != "" && device.Location != deviceInfo.Location {
		return 15.0 // Location changed - higher risk
	}

	return 0.0
}

// calculateTimeRisk calculates risk based on access time patterns
func (ra *RiskAnalyzer) calculateTimeRisk(deviceInfo *DeviceInfo) float64 {
	hour := time.Now().Hour()

	// Higher risk during unusual hours (11 PM - 5 AM)
	if hour >= 23 || hour < 5 {
		return 10.0
	}

	return 0.0
}

// calculateUserAgentRisk calculates risk based on user agent
func (ra *RiskAnalyzer) calculateUserAgentRisk(userAgent string) float64 {
	ua := strings.ToLower(userAgent)

	// Suspicious patterns
	if strings.Contains(ua, "bot") || strings.Contains(ua, "crawler") {
		return 15.0
	}

	if strings.Contains(ua, "curl") || strings.Contains(ua, "wget") {
		return 12.0
	}

	if userAgent == "" {
		return 10.0
	}

	// Known browsers - lower risk
	knownBrowsers := []string{"chrome", "firefox", "safari", "edge", "opera"}
	for _, browser := range knownBrowsers {
		if strings.Contains(ua, browser) {
			return 0.0
		}
	}

	return 5.0
}

// getRiskLevel returns the risk level based on score
func (ra *RiskAnalyzer) getRiskLevel(score float64) string {
	switch {
	case score >= 70:
		return "critical"
	case score >= 50:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

// getBlockReason returns the reason for blocking if applicable
func (ra *RiskAnalyzer) getBlockReason(factors map[string]float64, totalScore float64) string {
	if totalScore < 70 {
		return ""
	}

	var reasons []string
	if factors["ip_reputation"] >= 25 {
		reasons = append(reasons, "suspicious IP address")
	}
	if factors["device_trust"] >= 15 {
		reasons = append(reasons, "untrusted device")
	}
	if factors["location"] >= 10 {
		reasons = append(reasons, "unusual location")
	}
	if factors["user_agent"] >= 10 {
		reasons = append(reasons, "suspicious user agent")
	}

	if len(reasons) > 0 {
		return strings.Join(reasons, ", ")
	}

	return "high risk score"
}

// AddTrustedDevice adds a device to the trusted list
func (ra *RiskAnalyzer) AddTrustedDevice(deviceInfo *DeviceInfo) {
	deviceInfo.TrustedDevice = true
	deviceInfo.LastSeen = time.Now()
	ra.trustedDevices[deviceInfo.DeviceID] = deviceInfo
}

// AddTrustedIP adds an IP to the trusted list
func (ra *RiskAnalyzer) AddTrustedIP(ip string) {
	ra.trustedIPs[ip] = true
}

// BlockIP blocks an IP address
func (ra *RiskAnalyzer) BlockIP(ip string) {
	ra.blockedIPs[ip] = true
}

// GenerateDeviceFingerprint generates a device fingerprint
func GenerateDeviceFingerprint(userAgent, ip string, additionalData map[string]string) string {
	data := fmt.Sprintf("%s|%s", userAgent, ip)
	
	for k, v := range additionalData {
		data += fmt.Sprintf("|%s:%s", k, v)
	}

	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// isPrivateIP checks if an IP address is private
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
	}

	for _, cidr := range privateRanges {
		_, network, _ := net.ParseCIDR(cidr)
		if network.Contains(ip) {
			return true
		}
	}

	return false
}
