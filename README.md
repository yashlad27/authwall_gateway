# AuthWall: Zero-Trust Access Gateway

A microservice API gateway built in Go that enforces multi-factor authentication, adaptive risk scoring, and zero-trust security policies before granting access to internal APIs.

## Features

- **JWT Authentication**: Secure token-based authentication with validation and revocation
- **Multi-Factor Authentication (MFA)**: Google Authenticator-compatible TOTP implementation
- **Redis Session Management**: Distributed session storage with automatic expiration
- **Device Fingerprinting**: Track and score device trust based on usage patterns
- **Adaptive Risk Scoring**: Real-time risk assessment using multiple factors:
  - IP reputation analysis
  - Device trust scoring
  - Location change detection
  - Time-based pattern analysis
  - User agent analysis
- **Rate Limiting**: Token bucket algorithm preventing brute-force attacks
- **PostgreSQL User Management**: Secure user storage with Argon2 password hashing
- **Access Logging**: Complete audit trail of authentication attempts
- **Monitoring**: Prometheus metrics and Grafana dashboards
- **Zero-Trust Architecture**: Continuous verification of all access requests

## Technology Stack

- **Language**: Go 1.21+
- **Web Framework**: Gorilla Mux
- **Database**: PostgreSQL 16 (via GORM)
- **Cache**: Redis 7
- **Authentication**: JWT (golang-jwt/jwt)
- **MFA**: TOTP (pquerna/otp)
- **Monitoring**: Prometheus + Grafana
- **Container**: Docker & Docker Compose

## Architecture

```
Client Request
     |
     v
Rate Limiter
     |
     v
Risk Assessment
     |
     v
JWT Validation
     |
     v
Session Check
     |
     v
MFA Verification (if enabled)
     |
     v
Access Granted/Denied
     |
     v
Access Logging
```

### Components

- **JWT Manager**: Handles token generation, validation, and revocation
- **TOTP Manager**: Manages TOTP secrets and verification codes
- **Session Manager**: Redis-based distributed session storage
- **Risk Analyzer**: Calculates risk scores using multiple factors
- **Rate Limiter**: Token bucket implementation for request limiting
- **User Repository**: PostgreSQL user management with GORM
- **Access Log Repository**: Audit trail storage and querying

## Prerequisites

- Go 1.21 or higher
- Docker and Docker Compose
- PostgreSQL 16 (or use Docker)
- Redis 7 (or use Docker)

## Quick Start

### Using Docker Compose (Recommended)

```bash
# Start all services
make start

# Or manually
docker-compose up -d
```

This starts:
- AuthWall Gateway on port 8080
- PostgreSQL on port 5432
- Redis on port 6379
- Prometheus on port 9090
- Grafana on port 3000 (admin/admin)

### Local Development

```bash
# Copy environment file
cp .env.example .env

# Install dependencies
make deps

# Build the application
make build

# Run the server
make run
```

## API Endpoints

### Public Endpoints

#### Health Check
```bash
GET /health
```

#### User Registration
```bash
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "first_name": "John",
  "last_name": "Doe"
}
```

#### Login
```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "totp_code": "123456"  # Optional, required if MFA enabled
}
```

### Protected Endpoints (Require JWT)

#### Get User Profile
```bash
GET /api/user/profile
Authorization: Bearer <jwt_token>
```

#### Logout
```bash
POST /api/auth/logout
Authorization: Bearer <jwt_token>
```

#### Refresh Token
```bash
POST /api/auth/refresh
Authorization: Bearer <jwt_token>
```

### MFA Endpoints

#### Setup MFA
```bash
POST /api/mfa/setup
Authorization: Bearer <jwt_token>

Response:
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code_url": "otpauth://totp/AuthWall:user@example.com?secret=...",
  "recovery_codes": ["CODE1-CODE2", "CODE3-CODE4", ...]
}
```

#### Verify and Enable MFA
```bash
POST /api/mfa/verify
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "code": "123456"
}
```

#### Disable MFA
```bash
POST /api/mfa/disable
Authorization: Bearer <jwt_token>
Content-Type: application/json

{
  "code": "123456"
}
```

## Configuration

Environment variables (see `.env.example`):

```bash
# Server
SERVER_HOST=0.0.0.0
SERVER_PORT=8080

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=authwall
DB_PASSWORD=password
DB_NAME=authwall

# Redis
REDIS_URL=redis://localhost:6379/0

# JWT
JWT_SECRET=your-secret-key-change-this
JWT_DURATION=1h

# MFA
MFA_ISSUER=AuthWall

# Rate Limiting
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=1m
```

## Risk Scoring

The system calculates a risk score (0-100) based on:

| Factor | Weight | Description |
|--------|--------|-------------|
| IP Reputation | 30 points | Checks against blacklist and reputation database |
| Device Trust | 25 points | New vs known devices, time since last seen |
| Location | 15 points | Detects location changes |
| Time Pattern | 15 points | Flags unusual access times (11 PM - 5 AM) |
| User Agent | 15 points | Identifies bots, scripts, suspicious agents |

**Risk Levels:**
- **Low** (0-29): Normal access
- **Medium** (30-49): Additional verification may be required
- **High** (50-69): Elevated security checks
- **Critical** (70-100): Access blocked

## Monitoring

Access Grafana at `http://localhost:3000`:
- Username: `admin`
- Password: `admin`

Prometheus metrics available at `http://localhost:9090`

## Security Features

- **Password Hashing**: Bcrypt with cost factor 10
- **JWT Revocation**: Redis-based token blacklist
- **Session Security**: HTTP-only, secure, same-site cookies
- **Rate Limiting**: Per-IP request throttling
- **SQL Injection Protection**: Parameterized queries via GORM
- **CORS Protection**: Configurable cross-origin policies
- **Account Lockout**: 5 failed attempts = 15 minute lockout

## Development

### Running Tests
```bash
make test
```

### Building
```bash
make build
```

### Code Formatting
```bash
make fmt
```

### View Logs
```bash
make logs
```

## Project Structure

```
authwall_gateway/
├── cmd/
│   └── server/              # Main application
├── internal/
│   ├── auth/               # JWT management
│   ├── config/             # Configuration
│   ├── database/           # PostgreSQL models & repos
│   ├── handlers/           # HTTP handlers
│   ├── middleware/         # Auth, rate limit, risk middleware
│   ├── mfa/                # TOTP implementation
│   ├── risk/               # Risk scoring engine
│   └── session/            # Redis session management
├── docker-compose.yml      # Docker orchestration
├── Dockerfile             # Container image
├── Makefile               # Build automation
└── README.md              # This file
```

## Use Cases

- **Enterprise API Gateway**: Protect microservices with zero-trust policies
- **Banking Applications**: Multi-layer authentication for financial services
- **Healthcare Systems**: HIPAA-compliant access control
- **SaaS Platforms**: Tenant isolation and security
- **Internal Tools**: Secure access to admin panels

## Roadmap

- [ ] OAuth2/OIDC integration
- [ ] WebAuthn/FIDO2 support
- [ ] Geographic IP blocking
- [ ] Machine learning-based anomaly detection
- [ ] SMS/Email MFA alternatives
- [ ] Audit log export (CSV/JSON)
- [ ] Custom risk scoring rules
- [ ] API rate limiting per user

## License

MIT License

## Contact

Built as part of a cybersecurity portfolio project demonstrating:
- Zero-trust architecture
- Multi-factor authentication
- Risk-based access control
- Session management
- API security best practices
