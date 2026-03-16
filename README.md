# Auth Microservice

A standalone authentication microservice built in Go with JWT access tokens, refresh token rotation, role-based access control, rate limiting, and structured logging.

![Go](https://img.shields.io/badge/Go-1.25-blue)
![Gin](https://img.shields.io/badge/Gin-Framework-green)
![JWT](https://img.shields.io/badge/JWT-HS256-orange)
![Docker](https://img.shields.io/badge/Docker-Ready-blue)

## Why This Exists

Authentication is infrastructure that every production system needs but few portfolios implement properly. This microservice demonstrates JWT with refresh token rotation, RBAC middleware, brute-force protection via rate limiting, and operational readiness with health checks and metrics.

## Features

- **JWT access tokens** (1-hour expiry, HS256 signed)
- **Refresh token rotation** (cryptographic random tokens, one-time use)
- **Role-based access control** (user, admin roles with middleware enforcement)
- **Rate limiting** (sliding window per IP, configurable limits)
- **Structured logging** (method, path, status, latency per request)
- **Health check** endpoint for load balancers
- **Metrics** endpoint (uptime, request count, user count)
- **Thread-safe** in-memory store (swap for PostgreSQL/Redis in production)
- **Docker** multi-stage build (3MB final image)

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/health` | No | Health check |
| GET | `/metrics` | No | Uptime, request count, user count |
| POST | `/auth/register` | No | Create account (rate limited) |
| POST | `/auth/login` | No | Get access + refresh tokens (rate limited) |
| POST | `/auth/refresh` | No | Rotate refresh token for new token pair |
| GET | `/api/me` | JWT | Get current user profile |
| GET | `/api/admin/stats` | JWT + Admin | Admin-only statistics |

## Quick Start

### Run locally

```bash
git clone https://github.com/ctonneslan/auth-microservice.git
cd auth-microservice
go run .
```

Server starts at http://localhost:8080.

### Docker

```bash
docker build -t auth-service .
docker run -p 8080:8080 -e JWT_SECRET=your-secret auth-service
```

## Usage

```bash
# Register
curl -X POST localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","name":"Alice","password":"securepass"}'

# Login (returns access_token + refresh_token)
curl -X POST localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"securepass"}'

# Access protected route
curl localhost:8080/api/me \
  -H "Authorization: Bearer <access_token>"

# Refresh tokens (rotates refresh token)
curl -X POST localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token":"<refresh_token>"}'
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `JWT_SECRET` | `dev-secret-change-in-production` | HMAC signing key |

## Architecture

```
main.go                    # Server setup, route registration
├── handlers/
│   └── auth.go            # Register, Login, Refresh, Me handlers
├── middleware/
│   ├── auth.go            # JWT validation + RBAC middleware
│   ├── ratelimit.go       # Per-IP sliding window rate limiter
│   └── logging.go         # Structured request logging
├── models/
│   └── user.go            # Data types and request/response structs
└── store/
    └── store.go           # Thread-safe in-memory user + token store
```

## Security

- Passwords hashed with bcrypt (cost 12)
- JWT signed with HMAC-SHA256
- Refresh tokens are 256-bit cryptographic random
- Refresh token rotation (old token invalidated on use)
- Rate limiting on auth endpoints (20 req/min per IP)
- Protected routes require valid JWT in Authorization header
- Role-based access control for admin endpoints

## License

MIT
