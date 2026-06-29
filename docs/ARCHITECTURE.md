# Architecture

## Overview

email-auth-analyzer/
├── src/
│   ├── parser.py        # Load .eml, extract headers
│   ├── auth_checker.py  # SPF/DKIM/DMARC parsing + DNS lookups
│   ├── lookalike.py     # Levenshtein-based domain similarity
│   ├── analyzer.py      # Orchestrator + risk scoring
│   ├── cli.py           # Click CLI
│   └── app.py           # Flask web UI
├── templates/
│   └── index.html       # Dark dashboard UI
├── sample_emails/       # Test .eml files
└── requirements.txt

## Data Flow

.eml file
│
▼
parser.py          → extracts headers (From, Reply-To, Auth-Results)
│
▼
auth_checker.py    → parses SPF/DKIM/DMARC + live DNS lookups
│
▼
lookalike.py       → Levenshtein distance vs trusted brand list
│
▼
analyzer.py        → combines findings, calculates risk score (0-100)
│
├──▶ cli.py    → colored terminal output
└──▶ app.py    → Flask JSON API + web dashboard

## Risk Scoring

| Check                | Score |
|----------------------|-------|
| SPF fail             | +25   |
| DKIM fail            | +25   |
| DMARC fail           | +20   |
| Reply-To mismatch    | +20   |
| Lookalike domain     | +30   |
| No DMARC record      | +15   |
| No SPF record        | +10   |

Maximum score is capped at 100.

| Score  | Risk     |
|--------|----------|
| 70–100 | CRITICAL |
| 45–69  | HIGH     |
| 20–44  | MEDIUM   |
| 0–19   | LOW      |