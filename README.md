# 🕷️ CREEPER — Async OSINT Web Scraper v2.0

**Multi-purpose async crawler with Regex URL Hunting.**  
Give it any URL and one or more regex patterns — it crawls and returns every page URL where your patterns matched.

---

## What's New in v2.0

- **Regex Pattern Engine** — supply multiple regex patterns; get back URLs where content matched
- **Match-Only Mode** — only store pages that matched at least one pattern
- **Pattern Hit Summary** — per-pattern page counts, context snippets, match counts
- **Upgraded GUI** — tag-based pattern input, preset groups, copy/save buttons, hit highlighting
- **Flask API Server** — connect the GUI to the scraper over HTTP
- **Regex CSV export** — separate `_regex_matches.csv` with all hits
- **SQLite `regex_matches` table** — queryable hit records with context

---

## Install

```bash
pip install -r requirements.txt

# Optional: JS rendering for dynamic pages
pip install playwright && playwright install chromium
```

---

## Quick Start

### CLI

```bash
# Basic crawl
python scrape_cli.py https://example.com

# Find cybersecurity professionals (e.g. on a people-search site)
python scrape_cli.py https://linkedin.com/search/results/people/?keywords=security \
    -d 2 -p 100 \
    --regex "pentester" "CTF player" "bug bounty" "red team" "OSCP" "ethical hacker"

# Regex match-only mode — only keep pages that hit a pattern
python scrape_cli.py https://target.com \
    --regex "admin" "login" "password" \
    --match-only \
    --export json csv

# Hunt exposed secrets
python scrape_cli.py https://target.com \
    --regex "api_key\s*=" "secret\s*=" "token\s*=" "AWS_ACCESS_KEY" \
    -d 3 -p 200

# Full OSINT crawl with JS rendering
python scrape_cli.py https://target.com \
    -d 3 -p 200 --js \
    --export json csv sqlite
```

### GUI (Browser)

```bash
# Option A — Open directly (demo mode, no backend)
open CREEPER_scraper_gui.html

# Option B — With real backend
pip install flask
python server.py
# Visit http://localhost:5000
```

---

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `url` | — | Target URL to crawl |
| `-d / --depth` | `2` | Max crawl depth |
| `-p / --pages` | `50` | Max pages to crawl |
| `-c / --concurrency` | `5` | Async worker count |
| `--delay-min` | `0.5` | Min delay between requests (seconds) |
| `--delay-max` | `2.0` | Max delay between requests (seconds) |
| `--timeout` | `15` | Per-request timeout (seconds) |
| `--js` | off | Enable Playwright JS rendering |
| `--no-robots` | off | Ignore robots.txt |
| `--no-ssl-verify` | off | Disable SSL certificate verification |
| `--regex / -r` | `[]` | One or more regex patterns (Python `re` syntax) |
| `--match-only` | off | Only include pages matching a regex in results |
| `--export` | `json` | Export formats: `json` `csv` `sqlite` |
| `-o / --output` | `.` | Output directory |

---

## Regex Pattern Guide

Patterns use Python `re` module syntax with `re.IGNORECASE` by default.

| Goal | Pattern |
|------|---------|
| Keyword match | `pentester` |
| Phrase match | `bug bounty` |
| API key leak | `api_key\s*=` |
| Email address | `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}` |
| LinkedIn URL | `linkedin\.com/in/[\w\-]+` |
| Admin paths | `/admin\b` |
| JWT token | `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+` |
| AWS key | `AKIA[0-9A-Z]{16}` |
| Phone (US) | `\+?1?\s?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}` |

Patterns are tested against **both** the visible page text and the raw HTML source.

---

## Output Structure

### JSON Report (key sections)

```json
{
  "target": "https://example.com",
  "regex_patterns_used": ["pentester", "CTF player"],
  "regex_total_hits": 12,
  "regex_pattern_hit_count": {"pentester": 8, "CTF player": 5},
  "regex_matched_urls": [
    {
      "url": "https://example.com/profiles/john",
      "title": "John Doe — Profile",
      "matched_patterns": ["pentester", "CTF player"],
      "matches": [
        {
          "pattern": "pentester",
          "match_text": "pentester",
          "match_count": 3,
          "context": "…John is a senior pentester at …"
        }
      ]
    }
  ],
  "emails": [...],
  "phones": [...],
  "subdomains": [...],
  "api_endpoints": [...],
  "tech": {...},
  "pages": [...]
}
```

---

## Project Structure

```
CREEPER/
├── modules/
│   ├── __init__.py
│   └── web_scraper.py     ← Core scraper + regex engine
├── scrape_cli.py          ← CLI entry point
├── server.py              ← Flask API server (for GUI)
├── CREEPER_scraper_gui.html← Browser GUI
├── requirements.txt
└── README.md
```

---

## Ethics & Legal

- Always get permission before crawling a site you don't own
- Respect `robots.txt` (enabled by default)
- Use appropriate delays to avoid overloading servers
- Do not use for unauthorized access or data harvesting
