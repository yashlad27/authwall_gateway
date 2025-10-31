package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/yashlad/authwall-gateway/internal/auth"
	"github.com/yashlad/authwall-gateway/internal/config"
	"github.com/yashlad/authwall-gateway/internal/database"
	"github.com/yashlad/authwall-gateway/internal/handlers"
	"github.com/yashlad/authwall-gateway/internal/mfa"
	"github.com/yashlad/authwall-gateway/internal/middleware"
	"github.com/yashlad/authwall-gateway/internal/risk"
	"github.com/yashlad/authwall-gateway/internal/session"
)

func main() {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	log.Println("Starting AuthWall Gateway...")
	log.Printf("Server: %s:%d", cfg.Server.Host, cfg.Server.Port)

	// Connect to PostgreSQL
	db, err := database.ConnectPostgres(&database.Config{
		Host:     cfg.Database.Host,
		Port:     cfg.Database.Port,
		User:     cfg.Database.User,
		Password: cfg.Database.Password,
		DBName:   cfg.Database.DBName,
		SSLMode:  cfg.Database.SSLMode,
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	log.Println("✓ Connected to PostgreSQL")

	// Run migrations
	if err := database.AutoMigrate(db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}
	log.Println("✓ Database migrations completed")

	// Initialize Redis revoke store
	revokeStore, err := auth.NewRedisRevokeStore(cfg.Redis.URL, "authwall")
	if err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}
	defer revokeStore.Close()
	log.Println("✓ Connected to Redis (revoke store)")

	// Initialize session manager
	sessionManager, err := session.NewSessionManager(cfg.Redis.URL, "authwall", 1*time.Hour)
	if err != nil {
		log.Fatalf("Failed to initialize session manager: %v", err)
	}
	defer sessionManager.Close()
	log.Println("✓ Session manager initialized")

	// Initialize JWT manager
	jwtManager := auth.NewJWTManager(cfg.JWT.SecretKey, cfg.JWT.TokenDuration, revokeStore)
	log.Println("✓ JWT manager initialized")

	// Initialize TOTP manager
	totpManager := mfa.NewTOTPManager(cfg.MFA.Issuer)
	log.Println("✓ TOTP manager initialized")

	// Initialize risk analyzer
	ipReputationDB := risk.NewInMemoryIPReputation()
	riskAnalyzer := risk.NewRiskAnalyzer(ipReputationDB)
	log.Println("✓ Risk analyzer initialized")

	// Initialize repositories
	userRepo := database.NewUserRepository(db)
	accessLogRepo := database.NewAccessLogRepository(db)
	log.Println("✓ Repositories initialized")

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(userRepo, accessLogRepo, jwtManager, totpManager, sessionManager)
	mfaHandler := handlers.NewMFAHandler(userRepo, totpManager)
	userHandler := handlers.NewUserHandler(userRepo)
	log.Println("✓ Handlers initialized")

	// Initialize middleware
	authMiddleware := middleware.NewAuthMiddleware(jwtManager, sessionManager)
	riskMiddleware := middleware.NewRiskMiddleware(riskAnalyzer)
	rateLimiter := middleware.NewRateLimiter(cfg.RateLimit.RequestsPerWindow, cfg.RateLimit.Window)
	log.Println("✓ Middleware initialized")

	// Setup routes
	router := mux.NewRouter()

	// Public routes (no authentication required)
	router.HandleFunc("/health", healthCheckHandler).Methods("GET")
	router.HandleFunc("/api/auth/register", userHandler.Register).Methods("POST")
	
	// Login route with risk assessment and rate limiting
	loginRoute := http.HandlerFunc(authHandler.Login)
	router.Handle("/api/auth/login", 
		middleware.RateLimitMiddleware(rateLimiter)(
			riskMiddleware.AssessRisk(loginRoute),
		),
	).Methods("POST")

	// Protected routes (require authentication)
	protected := router.PathPrefix("/api").Subrouter()
	protected.Use(authMiddleware.Authenticate)

	// Auth routes
	protected.HandleFunc("/auth/logout", authHandler.Logout).Methods("POST")
	protected.HandleFunc("/auth/refresh", authHandler.RefreshToken).Methods("POST")

	// User routes
	protected.HandleFunc("/user/profile", userHandler.GetProfile).Methods("GET")

	// MFA routes
	protected.HandleFunc("/mfa/setup", mfaHandler.SetupMFA).Methods("POST")
	protected.HandleFunc("/mfa/verify", mfaHandler.VerifyAndEnableMFA).Methods("POST")
	protected.HandleFunc("/mfa/disable", mfaHandler.DisableMFA).Methods("POST")

	// Admin routes (require admin role)
	adminRoute := protected.PathPrefix("/admin").Subrouter()
	adminRoute.Use(authMiddleware.RequireRole("admin"))
	// Add admin endpoints here

	// Apply global middleware
	handler := middleware.RateLimitMiddleware(rateLimiter)(router)
	handler = loggingMiddleware(handler)

	// Start server
	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Handle graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan

		log.Println("\nShutting down gracefully...")
		server.Close()
	}()

	log.Printf("🚀 AuthWall Gateway running on %s", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server failed: %v", err)
	}

	log.Println("✓ Server stopped")
}

// healthCheckHandler handles health check requests
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))
}

// loggingMiddleware logs HTTP requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.RequestURI, time.Since(start))
	})
}
