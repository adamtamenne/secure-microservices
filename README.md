# Secure Microservices

Node.js microservices application for practicing security vulnerability identification and remediation. Start with an intentionally vulnerable codebase, run a security pipeline to identify findings, then fix each one with clear commits.

## Architecture

Two Express.js services communicating over a shared network:

- **auth-service** — User registration, login, JWT token management, password reset
- **notes-service** — CRUD API for user notes with file import/export, search, and attachments

Both services use MongoDB for persistence.

## Security Pipeline

Every push to `main` triggers a 5-stage security pipeline:

| Stage | Tool | What It Catches |
|-------|------|----------------|
| SAST | Semgrep | Code-level vulnerabilities (injection, hardcoded secrets, insecure crypto) |
| Secrets | Gitleaks | Credentials committed to source control |
| SCA | npm audit | Known CVEs in dependencies |
| IaC | Trivy | Dockerfile and infrastructure misconfigurations |
| Dockerfile | Hadolint | Dockerfile best practice violations |

## Running

```bash
docker-compose up --build
```

Auth service runs on port 3001, notes service on port 3002.

## API

### auth-service (port 3001)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/auth/register | Create a new user |
| POST | /api/auth/login | Authenticate and receive JWT |
| GET | /api/auth/profile/:id | Get user profile |
| GET | /api/auth/verify | Validate a JWT token |
| POST | /api/auth/reset-password | Generate a password reset token |
| GET | /api/auth/admin/users | List all users (admin) |
| GET | /api/auth/debug | Debug info |

### notes-service (port 3002)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/notes | List notes |
| GET | /api/notes/search | Search notes with filters |
| GET | /api/notes/export/:format | Export notes to a file format |
| GET | /api/notes/redirect | Redirect to a URL |
| GET | /api/notes/uploads | List uploaded files |
| GET | /api/notes/files/:filename | Download a note attachment |
| GET | /api/notes/:id | Get a single note |
| POST | /api/notes | Create a note |
| POST | /api/notes/import | Import note content from a URL |
| PUT | /api/notes/:id | Update a note |
| PUT | /api/notes/preferences | Update user preferences |
| DELETE | /api/notes/:id | Delete a note |
