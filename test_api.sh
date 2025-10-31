#!/bin/bash

set -e

echo "AuthWall Gateway - API Test Script"
echo "===================================="
echo ""

BASE_URL="http://localhost:8080"
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

log_test() {
    echo -e "${BLUE}$1${NC}"
}

log_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

log_error() {
    echo -e "${RED}✗ $1${NC}"
}

# Test 1: Health Check
log_test "1. Testing Health Check..."
HEALTH_RESPONSE=$(curl -s $BASE_URL/health)
if echo "$HEALTH_RESPONSE" | grep -q "healthy"; then
    log_success "Health check passed"
else
    log_error "Health check failed"
    exit 1
fi
echo ""

# Test 2: User Registration
log_test "2. Testing User Registration..."
REGISTER_RESPONSE=$(curl -s -X POST $BASE_URL/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!",
    "first_name": "Test",
    "last_name": "User"
  }')

if echo "$REGISTER_RESPONSE" | grep -q "created successfully"; then
    log_success "User registration successful"
else
    log_error "User registration failed"
    echo "Response: $REGISTER_RESPONSE"
fi
echo ""

# Test 3: Login
log_test "3. Testing Login..."
LOGIN_RESPONSE=$(curl -s -X POST $BASE_URL/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "SecurePass123!"
  }')

TOKEN=$(echo "$LOGIN_RESPONSE" | grep -o '"token":"[^"]*' | cut -d'"' -f4)

if [ ! -z "$TOKEN" ]; then
    log_success "Login successful"
    echo "Token: ${TOKEN:0:50}..."
else
    log_error "Login failed"
    echo "Response: $LOGIN_RESPONSE"
    exit 1
fi
echo ""

# Test 4: Get Profile
log_test "4. Testing Get Profile..."
PROFILE_RESPONSE=$(curl -s -X GET $BASE_URL/api/user/profile \
  -H "Authorization: Bearer $TOKEN")

if echo "$PROFILE_RESPONSE" | grep -q "test@example.com"; then
    log_success "Profile retrieval successful"
else
    log_error "Profile retrieval failed"
    echo "Response: $PROFILE_RESPONSE"
fi
echo ""

# Test 5: MFA Setup
log_test "5. Testing MFA Setup..."
MFA_SETUP_RESPONSE=$(curl -s -X POST $BASE_URL/api/mfa/setup \
  -H "Authorization: Bearer $TOKEN")

if echo "$MFA_SETUP_RESPONSE" | grep -q "secret"; then
    log_success "MFA setup successful"
    SECRET=$(echo "$MFA_SETUP_RESPONSE" | grep -o '"secret":"[^"]*' | cut -d'"' -f4)
    echo "MFA Secret: $SECRET"
else
    log_error "MFA setup failed"
    echo "Response: $MFA_SETUP_RESPONSE"
fi
echo ""

# Test 6: Refresh Token
log_test "6. Testing Token Refresh..."
REFRESH_RESPONSE=$(curl -s -X POST $BASE_URL/api/auth/refresh \
  -H "Authorization: Bearer $TOKEN")

NEW_TOKEN=$(echo "$REFRESH_RESPONSE" | grep -o '"token":"[^"]*' | cut -d'"' -f4)

if [ ! -z "$NEW_TOKEN" ]; then
    log_success "Token refresh successful"
else
    log_error "Token refresh failed"
    echo "Response: $REFRESH_RESPONSE"
fi
echo ""

# Test 7: Logout
log_test "7. Testing Logout..."
LOGOUT_RESPONSE=$(curl -s -X POST $BASE_URL/api/auth/logout \
  -H "Authorization: Bearer $TOKEN")

if echo "$LOGOUT_RESPONSE" | grep -q "successful"; then
    log_success "Logout successful"
else
    log_error "Logout failed"
    echo "Response: $LOGOUT_RESPONSE"
fi
echo ""

# Test 8: Rate Limiting
log_test "8. Testing Rate Limiting..."
echo "Sending 105 requests to trigger rate limit..."
RATE_LIMIT_HIT=false

for i in {1..105}; do
    RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/health)
    if [ "$RESPONSE" == "429" ]; then
        RATE_LIMIT_HIT=true
        log_success "Rate limiting working (hit at request $i)"
        break
    fi
done

if [ "$RATE_LIMIT_HIT" == "false" ]; then
    echo "Rate limit not triggered (may need adjustment)"
fi
echo ""

echo "===================================="
echo -e "${GREEN}All tests completed!${NC}"
echo "===================================="
