# 🛡️ Email Authentication Analyzer

A tool for detecting Business Email Compromise (BEC) attacks and email 
authentication failures. Analyzes SPF, DKIM, DMARC records and detects 
lookalike domains used in phishing attacks.

## Features

- **SPF/DKIM/DMARC Analysis** — parses Authentication-Results headers and checks live DNS records
- **Lookalike Domain Detection** — catches typosquatting domains like `paypa1-security.com` → `paypal.com`
- **Reply-To Mismatch Detection** — flags emails where replies go to a different domain
- **Risk Scoring** — 0–100 score with CRITICAL/HIGH/MEDIUM/LOW rating
- **CLI Interface** — analyze .eml files from the terminal
- **Web Interface** — drag-and-drop browser UI

## Setup

```bash
git clone https://github.com/chamika-r/email-auth-analyzer.git
cd email-auth-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

### CLI
```bash
PYTHONPATH=. python3 -m src.cli sample_emails/test_suspicious.eml
```

### Web UI
```bash
PYTHONPATH=. python3 src/app.py
```
Open `http://127.0.0.1:5000` and upload any `.eml` file.

### JSON Output
```bash
PYTHONPATH=. python3 -m src.cli sample_emails/test_suspicious.eml --json-output
```

## How It Works

1. **Parser** — loads the `.eml` file and extracts authentication headers
2. **Auth Checker** — parses SPF/DKIM/DMARC verdicts and performs live DNS lookups
3. **Lookalike Detector** — uses Levenshtein distance to detect brand impersonation
4. **Analyzer** — orchestrates all checks and produces a risk score

## Real-World Detection

Tested against simulated BEC emails. Catches:
- Spoofed sender domains with no SPF/DMARC records
- DKIM signature failures indicating tampered emails
- Reply-To hijacking (replies go to attacker's server)
- Typosquatted domains (`paypa1.com`, `micros0ft-login.com`)

## Architecture

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)