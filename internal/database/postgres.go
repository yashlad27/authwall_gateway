package database

import (
	"fmt"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Config holds database configuration
type Config struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

// ConnectPostgres connects to PostgreSQL database
func ConnectPostgres(config *Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		config.Host, config.Port, config.User, config.Password, config.DBName, config.SSLMode,
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Hour)

	return db, nil
}

// AutoMigrate runs database migrations
func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&User{},
		&AccessLog{},
	)
}

// AccessLog represents an access log entry
type AccessLog struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	UserID       uint      `gorm:"index" json:"user_id"`
	Email        string    `gorm:"index" json:"email"`
	IPAddress    string    `gorm:"index" json:"ip_address"`
	DeviceID     string    `gorm:"index" json:"device_id"`
	UserAgent    string    `json:"user_agent"`
	Endpoint     string    `json:"endpoint"`
	Method       string    `json:"method"`
	StatusCode   int       `json:"status_code"`
	RiskScore    float64   `json:"risk_score"`
	RiskLevel    string    `json:"risk_level"`
	MFAVerified  bool      `json:"mfa_verified"`
	Action       string    `json:"action"` // login, logout, access, denied
	Timestamp    time.Time `gorm:"index" json:"timestamp"`
}

// AccessLogRepository handles database operations for access logs
type AccessLogRepository struct {
	db *gorm.DB
}

// NewAccessLogRepository creates a new access log repository
func NewAccessLogRepository(db *gorm.DB) *AccessLogRepository {
	return &AccessLogRepository{db: db}
}

// Create creates a new access log entry
func (r *AccessLogRepository) Create(log *AccessLog) error {
	return r.db.Create(log).Error
}

// GetByUserID retrieves access logs for a user
func (r *AccessLogRepository) GetByUserID(userID uint, limit, offset int) ([]AccessLog, int64, error) {
	var logs []AccessLog
	var total int64

	if err := r.db.Model(&AccessLog{}).Where("user_id = ?", userID).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	err := r.db.Where("user_id = ?", userID).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error

	return logs, total, err
}

// GetByIP retrieves access logs for an IP address
func (r *AccessLogRepository) GetByIP(ipAddress string, limit, offset int) ([]AccessLog, int64, error) {
	var logs []AccessLog
	var total int64

	if err := r.db.Model(&AccessLog{}).Where("ip_address = ?", ipAddress).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	err := r.db.Where("ip_address = ?", ipAddress).
		Order("timestamp DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error

	return logs, total, err
}

// GetRecent retrieves recent access logs
func (r *AccessLogRepository) GetRecent(limit int) ([]AccessLog, error) {
	var logs []AccessLog
	err := r.db.Order("timestamp DESC").Limit(limit).Find(&logs).Error
	return logs, err
}

// GetHighRiskLogs retrieves high-risk access attempts
func (r *AccessLogRepository) GetHighRiskLogs(minScore float64, limit int) ([]AccessLog, error) {
	var logs []AccessLog
	err := r.db.Where("risk_score >= ?", minScore).
		Order("timestamp DESC").
		Limit(limit).
		Find(&logs).Error
	return logs, err
}

// GetStatsByTimeRange retrieves statistics for a time range
func (r *AccessLogRepository) GetStatsByTimeRange(start, end time.Time) (map[string]interface{}, error) {
	var stats struct {
		TotalRequests   int64
		SuccessfulLogins int64
		FailedLogins    int64
		BlockedRequests int64
		AverageRiskScore float64
	}

	// Total requests
	r.db.Model(&AccessLog{}).
		Where("timestamp BETWEEN ? AND ?", start, end).
		Count(&stats.TotalRequests)

	// Successful logins
	r.db.Model(&AccessLog{}).
		Where("timestamp BETWEEN ? AND ? AND action = ? AND status_code = ?", start, end, "login", 200).
		Count(&stats.SuccessfulLogins)

	// Failed logins
	r.db.Model(&AccessLog{}).
		Where("timestamp BETWEEN ? AND ? AND action = ? AND status_code != ?", start, end, "login", 200).
		Count(&stats.FailedLogins)

	// Blocked requests
	r.db.Model(&AccessLog{}).
		Where("timestamp BETWEEN ? AND ? AND action = ?", start, end, "denied").
		Count(&stats.BlockedRequests)

	// Average risk score
	r.db.Model(&AccessLog{}).
		Where("timestamp BETWEEN ? AND ?", start, end).
		Select("AVG(risk_score)").
		Scan(&stats.AverageRiskScore)

	return map[string]interface{}{
		"total_requests":    stats.TotalRequests,
		"successful_logins": stats.SuccessfulLogins,
		"failed_logins":     stats.FailedLogins,
		"blocked_requests":  stats.BlockedRequests,
		"average_risk_score": stats.AverageRiskScore,
	}, nil
}
