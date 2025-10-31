.PHONY: build run test clean docker-build docker-up docker-down migrate help

# Variables
BINARY_NAME=authwall-server
GO=go
GOFLAGS=-v
DOCKER_COMPOSE=docker-compose

# Build the application
build:
	@echo "Building..."
	$(GO) build $(GOFLAGS) -o bin/$(BINARY_NAME) ./cmd/server
	@echo "✓ Build complete"

# Run the application
run: build
	@echo "Running server..."
	./bin/$(BINARY_NAME)

# Run tests
test:
	@echo "Running tests..."
	$(GO) test -v ./...

# Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GO) test -v -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report generated: coverage.html"

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html
	@echo "✓ Cleaned"

# Docker commands
docker-build:
	@echo "Building Docker image..."
	$(DOCKER_COMPOSE) build
	@echo "✓ Docker image built"

docker-up:
	@echo "Starting services..."
	$(DOCKER_COMPOSE) up -d
	@echo "✓ Services started"
	@echo ""
	@echo "Services running:"
	@echo "  AuthWall:   http://localhost:8080"
	@echo "  Grafana:    http://localhost:3000 (admin/admin)"
	@echo "  Prometheus: http://localhost:9090"
	@echo "  PostgreSQL: localhost:5432"
	@echo "  Redis:      localhost:6379"

docker-down:
	@echo "Stopping services..."
	$(DOCKER_COMPOSE) down
	@echo "✓ Services stopped"

docker-logs:
	$(DOCKER_COMPOSE) logs -f authwall

docker-restart:
	@echo "Restarting services..."
	$(DOCKER_COMPOSE) restart
	@echo "✓ Services restarted"

# Database migration
migrate-up:
	@echo "Running migrations..."
	$(GO) run ./cmd/server --migrate
	@echo "✓ Migrations complete"

# Install dependencies
deps:
	@echo "Installing dependencies..."
	$(GO) mod download
	$(GO) mod tidy
	@echo "✓ Dependencies installed"

# Format code
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...
	@echo "✓ Code formatted"

# Lint code
lint:
	@echo "Linting code..."
	golangci-lint run
	@echo "✓ Linting complete"

# Development setup
dev-setup: deps
	@echo "Setting up development environment..."
	@echo "✓ Development environment ready"

# Start all services
start: docker-up
	@echo "✓ AuthWall Gateway is running!"

# Stop all services
stop: docker-down

# View logs
logs:
	$(DOCKER_COMPOSE) logs -f

# Help
help:
	@echo "AuthWall Gateway - Available Commands:"
	@echo ""
	@echo "  make build          - Build the application"
	@echo "  make run            - Run the application locally"
	@echo "  make test           - Run tests"
	@echo "  make test-coverage  - Run tests with coverage"
	@echo "  make clean          - Clean build artifacts"
	@echo ""
	@echo "  make docker-build   - Build Docker image"
	@echo "  make docker-up      - Start Docker services"
	@echo "  make docker-down    - Stop Docker services"
	@echo "  make docker-logs    - View logs"
	@echo "  make docker-restart - Restart services"
	@echo ""
	@echo "  make deps           - Install dependencies"
	@echo "  make fmt            - Format code"
	@echo "  make lint           - Lint code"
	@echo ""
	@echo "  make start          - Quick start (docker-up)"
	@echo "  make stop           - Quick stop (docker-down)"
	@echo "  make logs           - View all logs"
