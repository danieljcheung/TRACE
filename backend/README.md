# TRACE Backend

Secure OSINT identity mapping tool. Zero data retention.

## Quick Start

```bash
cd backend
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

API runs at http://localhost:8000

## Endpoints

- `GET /api/health` - Health check
- `POST /api/verify/send` - Send verification code
- `POST /api/verify/confirm` - Confirm code, get scan token

## Test Verification

```bash
# Send code (check terminal for code in dev mode)
curl -X POST http://localhost:8000/api/verify/send \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com"}'

# Confirm code
curl -X POST http://localhost:8000/api/verify/confirm \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "code": "123456"}'
```

## Security

- All codes stored as salted hashes
- Rate limiting on all endpoints
- No data persistence
- Security headers on all responses
