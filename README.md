# TRACE

**T**otal **R**econnaissance and **A**nalysis for **C**yber **E**xposure

A privacy-focused OSINT (Open Source Intelligence) tool that maps your digital footprint from a single email address. Discover what information about you is publicly accessible online.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-green.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109-teal.svg)

---

## Features

- **Email Verification** - Secure verification flow ensures you can only scan your own email
- **Multi-Hop OSINT Scanning** - 1-3 depth levels for thorough digital footprint analysis
- **7 OSINT Modules** - Breach detection, social media, code platforms, and more
- **Real-Time Results** - Server-Sent Events (SSE) stream findings as they're discovered
- **Risk Scoring** - 0-100 risk score with severity breakdown
- **Terminal UI** - Retro cyberpunk interface with typing effects
- **Interactive Graph** - D3.js force-directed visualization of identity connections
- **PDF Export** - Download a detailed receipt of findings
- **Zero Data Retention** - All scan data cleared from memory after completion

---

## Architecture

```
TRACE/
├── index.html              # Frontend entry point
├── css/
│   ├── main.css            # Base styles & variables
│   ├── terminal.css        # Terminal typing effects
│   ├── components.css      # UI components
│   ├── graph.css           # D3 graph styles
│   └── receipt.css         # PDF receipt styles
├── js/
│   ├── app.js              # Main application controller
│   ├── router.js           # Client-side SPA routing
│   ├── api.js              # Backend API communication
│   ├── terminal.js         # Terminal typing effects
│   ├── graph.js            # D3.js graph visualization
│   ├── receipt.js          # Results receipt renderer
│   ├── pdf.js              # PDF generation (html2pdf)
│   └── audio.js            # Sound effects
└── backend/
    ├── main.py             # FastAPI application
    ├── config.py           # Environment configuration
    ├── requirements.txt    # Python dependencies
    ├── models/
    │   ├── requests.py     # Pydantic request models
    │   ├── responses.py    # Pydantic response models
    │   └── findings.py     # OSINT finding model
    ├── routes/
    │   ├── health.py       # Health check endpoint
    │   ├── verify.py       # Email verification endpoints
    │   └── scan.py         # SSE scan endpoint
    ├── security/
    │   ├── headers.py      # Security headers middleware
    │   ├── rate_limit.py   # Sliding window rate limiter
    │   └── verification.py # Verification code store
    ├── services/
    │   └── email.py        # Resend email service
    └── osint/
        ├── orchestrator.py # Scan coordination
        ├── risk.py         # Risk score calculation
        └── modules/
            ├── base.py               # Base module class
            ├── username_extractor.py # Extract usernames from email
            ├── username_checker.py   # Check 30+ platforms
            ├── breach_lookup.py      # HIBP k-anonymity API
            ├── gravatar.py           # Gravatar profile lookup
            ├── github.py             # GitHub API lookup
            ├── whois_lookup.py       # Domain/DNS lookup
            └── pgp_keys.py           # PGP keyserver search
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- Modern web browser
- (Optional) Resend API key for email delivery
- (Optional) GitHub token for higher API rate limits

### 1. Clone the Repository

```bash
git clone https://github.com/danieljcheung/TRACE.git
cd TRACE
```

### 2. Start the Backend

```bash
cd backend

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (macOS/Linux)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run server
python main.py
```

Backend runs at http://localhost:8000

### 3. Start the Frontend

```bash
# From project root, serve with Python
python -m http.server 5500

# Or with Node.js
npx serve -p 5500
```

Frontend runs at http://localhost:5500

### 4. Open in Browser

Navigate to http://localhost:5500 and enter your email to begin a scan.

---

## API Endpoints

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/health` | GET | No | Health check |
| `/api/verify/send` | POST | No | Send verification code to email |
| `/api/verify/confirm` | POST | No | Confirm code, receive scan token |
| `/api/scan` | GET | Token | Execute scan with SSE streaming |
| `/api/scan/demo` | GET | No | Demo scan (no verification) |

### Example: Full Scan Flow

```bash
# 1. Request verification code
curl -X POST http://localhost:8000/api/verify/send \
  -H "Content-Type: application/json" \
  -d '{"email": "your@email.com"}'

# 2. Confirm code (check terminal for code in dev mode)
curl -X POST http://localhost:8000/api/verify/confirm \
  -H "Content-Type: application/json" \
  -d '{"email": "your@email.com", "code": "123456"}'

# Response: {"success": true, "scan_token": "abc123...", ...}

# 3. Run scan with token
curl -N "http://localhost:8000/api/scan?token=abc123...&depth=2"
```

### SSE Event Types

```javascript
event: start     // Scan initiated
event: finding   // New finding discovered
event: progress  // Progress update (0-100%)
event: complete  // Scan finished with results
event: error     // Error occurred
```

---

## OSINT Modules

| Module | Description | Data Found |
|--------|-------------|------------|
| **Username Extractor** | Parse email to find potential usernames | Usernames from email prefix |
| **Username Checker** | Check 30+ platforms for accounts | Social media, code platforms, etc. |
| **Breach Lookup** | HIBP k-anonymity API | Data breach exposure |
| **Gravatar** | Gravatar profile lookup | Name, location, photo, linked URLs |
| **GitHub** | GitHub API lookup | Profile, repos, name, company, email |
| **WHOIS/DNS** | Domain lookup | Custom domains, potentially owned domains |
| **PGP Keys** | Keyserver search | Public PGP keys |

### Platforms Checked

GitHub, GitLab, Bitbucket, Docker Hub, npm, PyPI, Dev.to, Twitter/X, Instagram, TikTok, Reddit, Pinterest, Tumblr, LinkedIn, Medium, About.me, Twitch, Steam, Dribbble, Behance, SoundCloud, Spotify, Vimeo, Flickr, Keybase, Patreon, Linktree, Gravatar, HackerNews

---

## Configuration

### Backend Environment Variables

Create `backend/.env` (copy from `.env.example`):

```bash
# Environment
ENVIRONMENT=development
DEBUG=true

# Email (get key at resend.com)
RESEND_API_KEY=re_xxxxx

# GitHub (for higher rate limits)
GITHUB_TOKEN=ghp_xxxxx
```

### Frontend Configuration

Edit `js/api.js` to change the backend URL:

```javascript
const CONFIG = {
    BASE_URL: 'http://localhost:8000/api',
    // ...
};
```

---

## Risk Scoring

The risk score (0-100) is calculated based on:

| Severity | Points | Max |
|----------|--------|-----|
| Critical | 25 each | 50 |
| High | 10 each | 30 |
| Medium | 3 each | 15 |
| Low | 1 each | 5 |

**Bonus Penalties:**
- Password exposed in breach: +15
- Home address found: +15
- Phone number found: +10
- Name + Location combo: +5
- 10+ accounts discovered: +5

**Risk Levels:**
- 0-29: LOW
- 30-49: MEDIUM
- 50-69: HIGH
- 70-100: CRITICAL

---

## Security Features

- **Verification Required** - Can only scan emails you can verify ownership of
- **Rate Limiting** - 10 verification requests/hour, 1 scan/email/24h
- **Salted Hashes** - Verification codes stored as salted SHA-256 hashes
- **Security Headers** - X-Content-Type-Options, X-Frame-Options, CSP, etc.
- **Zero Retention** - All scan data cleared from memory after completion
- **k-Anonymity** - HIBP queries use k-anonymity (only first 5 chars of hash sent)

---

## Development

### Running Tests

```bash
cd backend
python -m pytest
```

### API Documentation

With the backend running, visit:
- Swagger UI: http://localhost:8000/docs
- OpenAPI JSON: http://localhost:8000/openapi.json

### Demo Mode

Test without email verification:
```bash
curl -N "http://localhost:8000/api/scan/demo"
```

---

## Screenshots

### Terminal Interface
```
+========================================+
|                                        |
|   TRACE v1.0                           |
|   OSINT Identity Mapper                |
|                                        |
|   > Enter target email:                |
|   > _                                  |
|                                        |
+========================================+
```

### Risk Score Output
```
========================================
RISK ASSESSMENT
========================================
Score: 67/100 [################--------] HIGH

CRITICAL: 1 finding(s)
HIGH:     3 finding(s)
MEDIUM:   8 finding(s)
LOW:      12 finding(s)
========================================
```

---

## Tech Stack

**Frontend:**
- Vanilla JavaScript (ES6+)
- D3.js for graph visualization
- html2pdf.js for PDF export
- CSS3 with custom properties

**Backend:**
- Python 3.11+
- FastAPI
- Pydantic v2
- httpx (async HTTP)
- Resend (email delivery)

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Disclaimer

TRACE is designed for personal use to discover your own digital footprint. Only scan email addresses you own or have explicit permission to scan. The developers are not responsible for misuse of this tool.

---

## Contributing

Contributions welcome! Please read our contributing guidelines before submitting PRs.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Acknowledgments

- [Have I Been Pwned](https://haveibeenpwned.com) for the k-anonymity API
- [Gravatar](https://gravatar.com) for profile data
- [GitHub API](https://docs.github.com/en/rest) for developer profiles
- [OpenPGP Keyserver](https://keys.openpgp.org) for PGP key lookups
