# CREEPER v3 — Modular Bug-Hunt Recon Crawler

Stealth async web scraper for **authenticated bug hunting / authorized penetration testing**.

---

## Module Layout

```
kernox_web_scraper/
├── CREEPER_scraper_gui.html   ← GUI (open via server.py or directly in browser)
├── scrape_cli.py              ← CLI entry point
├── server.py                  ← Flask API server (bridges GUI ↔ Python)
├── requirements.txt
└── modules/
    ├── __init__.py            ← Public API re-exports
    ├── models.py              ← Shared dataclasses (ScrapedPage, TechFingerprint, …)
    ├── constants.py           ← UA pool, signatures, compiled regexes — no logic
    ├── stealth.py             ← StealthHeaders + DomainRateLimiter (WAF evasion)
    ├── regex_engine.py        ← User-pattern compilation & page matching
    ├── extractor.py           ← HTML parsing: emails, phones, forms, APIs, JS vars, …
    ├── waf_detect.py          ← Deep WAF/CAPTCHA fingerprinting + bypass hints
    ├── bfs.py                 ← BFS crawler with correct worker lifecycle
    ├── spider.py              ← Per-page fetch + parse orchestrator
    ├── orchestrator.py        ← AsyncOSINTScraper — wires everything together
    ├── reporter.py            ← Report aggregation + Rich terminal display
    ├── exporter.py            ← JSON / CSV / SQLite export
    └── web_scraper.py         ← Backward-compat shim (old imports still work)
```

---

## Install

```bash
pip install -r requirements.txt

# Optional: JS rendering for SPA targets
pip install playwright && playwright install chromium
```

---

## GUI (recommended)

```bash
python server.py
# Open http://localhost:5000
```

---

## CLI

```bash
# Basic crawl
python scrape_cli.py https://target.com

# Hunt for exposed secrets
python scrape_cli.py https://target.com -d 3 -p 150 \
    --regex "api_key\s*=" "secret\s*=" "AKIA[0-9A-Z]{16}" "eyJ[a-zA-Z0-9\-_]+"

# Match-only mode — only collect pages where a pattern fired
python scrape_cli.py https://target.com --regex "/admin" "/debug" --match-only

# Authenticated crawl (pass session cookie / auth token)
python scrape_cli.py https://target.com \
    --header "Cookie=session=abc123def456" \
    --header "Authorization=Bearer eyJhbGci..."

# Slow + stealthy (raise delays, lower concurrency)
python scrape_cli.py https://target.com \
    --delay-min 2.0 --delay-max 6.0 -c 2 -d 4 -p 300

# Full export
python scrape_cli.py https://target.com --export json csv sqlite -o ./output/
```

### All CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `-d / --depth` | 2 | Max crawl depth |
| `-p / --pages` | 50 | Max pages to crawl |
| `-c / --concurrency` | 5 | Parallel async workers (max 20) |
| `--delay-min` | 1.0 | Min per-domain delay (seconds) |
| `--delay-max` | 3.0 | Max per-domain delay (seconds) |
| `--timeout` | 20 | Per-request timeout (seconds) |
| `--js` | off | Enable Playwright JS rendering |
| `--no-robots` | off | Ignore robots.txt |
| `--no-ssl-verify` | off | Skip TLS certificate validation |
| `--match-only` | off | Only store pages matching a regex |
| `--regex / -r` | — | One or more Python regex patterns |
| `--header K=V` | — | Custom request headers (repeatable) |
| `--export` | json | Export formats: json csv sqlite |
| `-o / --output` | . | Output directory |
| `--json-only` | off | Print JSON to stdout and exit |

---

## Python API

```python
from modules import AsyncOSINTScraper, format_report

scraper = AsyncOSINTScraper(
    concurrency=5,
    delay_range=(1.0, 3.0),
    regex_patterns=[r"api_key\s*=", r"password\s*=", r"AKIA[0-9A-Z]{16}"],
    regex_match_only=False,
    custom_headers={"Cookie": "session=abc123", "Authorization": "Bearer ..."},
    verify_ssl=True,
    respect_robots=True,
)

report = scraper.scrape(
    start_url="https://target.com",
    max_depth=3,
    max_pages=100,
    output_dir="./output",
    export_formats=["json", "csv"],
)

format_report(report)
print(report["regex_matched_urls"])   # pages where patterns fired
print(report["forms_without_csrf"])   # forms missing CSRF tokens
print(report["js_sensitive_vars"])    # secrets/keys found in JS
print(report["api_endpoints"])        # discovered API routes
```

---

## Stealth / WAF Evasion

- **Per-domain adaptive rate limiting** — backoff multiplier doubles on 429/403/WAF signals, gradually recovers on clean responses
- **Realistic browser headers** — matching Sec-CH-UA / platform hints per UA variant
- **Header randomisation** — Accept, Accept-Language, Cache-Control, Sec-Fetch-Site vary per request
- **Retry with jitter** — single retry on transient network errors with random delay
- **robots.txt respected by default** — disable with `--no-robots` for authorized scans
- **Playwright fallback** — re-renders JS-heavy SPAs when aiohttp response looks empty
- **Deep WAF detection** (`waf_detect.py`) — identifies Cloudflare, Akamai, Imperva, AWS WAF, F5, Sucuri, Barracuda, ModSecurity, Wordfence + CAPTCHA variants, generates bypass hints

---

## What it finds

| Category | Details |
|----------|---------|
| **Regex matches** | Any custom pattern — secrets, paths, tokens, errors |
| **Forms** | Action, method, fields, password inputs, file uploads, CSRF status, hidden values |
| **JS secrets** | Hardcoded API keys, AWS/GCP/GitHub/OpenAI tokens, JWTs, source maps |
| **API endpoints** | `/api/*`, `/v1/*`, `/graphql`, `/rest/*`, `/webhook`, `/internal` |
| **Emails / phones** | Extracted from full HTML |
| **Subdomains** | Referenced in HTML/JS matching base domain |
| **HTML comments** | Often contain TODO notes, keys, internal paths |
| **Tech fingerprint** | CMS, WAF, CDN, frameworks, server, security headers audit |

---

## ⚠ Legal Notice

This tool is for **authorized security testing only**.  
Only scan targets you own or have explicit written permission to test.  
Unauthorized scanning may violate computer crime laws in your jurisdiction.
