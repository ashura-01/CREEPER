"""
modules/constants.py
All static data: user-agents, header pools, WAF/CMS/CDN signatures,
compiled regexes. Import-only — no logic here.
"""

from __future__ import annotations
import re
from typing import List, Dict

# ── User-Agent pool (2024-2025 realistic browser strings) ────────────────────

USER_AGENTS: List[str] = [
    # Chrome / Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36",
    # Chrome / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    # Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    # Safari / macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    # Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

# Sec-CH-UA values that match each Chrome UA variant
SEC_CH_UA_MAP: Dict[str, str] = {
    "Chrome/124": '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"',
    "Chrome/123": '"Chromium";v="123", "Google Chrome";v="123", "Not-A.Brand";v="99"',
    "Edg/124":    '"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"',
}

ACCEPT_HEADERS: List[str] = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
]

ACCEPT_LANG_HEADERS: List[str] = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.8",
]

# ── WAF / rate-limit detection ────────────────────────────────────────────────

WAF_BLOCK_STATUSES = {403, 406, 429, 503}

WAF_BLOCK_BODY_PHRASES = [
    "access denied", "blocked", "captcha", "ddos-guard", "ray id",
    "cloudflare", "incapsula", "sucuri", "akamai error", "rate limit",
    "too many requests", "security check", "bot protection",
]

# ── Technology fingerprint signatures ─────────────────────────────────────────

CMS_SIGNATURES: Dict[str, List[str]] = {
    "WordPress":  ["/wp-content/", "/wp-includes/", "wp-login.php"],
    "Joomla":     ["/components/com_", "Joomla!", "/media/jui/"],
    "Drupal":     ["Drupal.settings", "/sites/default/files/", "drupal.js"],
    "Shopify":    ["cdn.shopify.com", "Shopify.theme"],
    "Magento":    ["Mage.Cookies", "/skin/frontend/", "magento"],
    "Django":     ["csrfmiddlewaretoken", "__django"],
    "Laravel":    ["laravel_session", "XSRF-TOKEN"],
    "Rails":      ["authenticity_token", "rails-ujs"],
    "React":      ["__REACT_DEVTOOLS", "react-root", "_reactFiber",
                   "__NEXT_DATA__", "_next/static"],
    "Vue.js":     ["__vue__", "v-cloak", "data-v-", "__NUXT__", "_nuxt/"],
    "Angular":    ["ng-version", "ng-app", "angular.min.js"],
    "ASP.NET":    ["__VIEWSTATE", "__EVENTVALIDATION", "ASP.NET_SessionId"],
}

WAF_SIGNATURES: Dict[str, List[str]] = {
    "Cloudflare":  ["cf-ray", "cloudflare", "__cfduid", "cf-cache-status"],
    "AWS WAF":     ["x-amzn-requestid", "x-amz-cf-id", "awswaf"],
    "Akamai":      ["akamai", "x-akamai-request-id", "x-check-cacheable"],
    "Imperva":     ["x-iinfo", "incap_ses", "visid_incap", "incapsula"],
    "Sucuri":      ["x-sucuri-id", "sucuri-clientid", "x-sucuri-cache"],
    "F5 BIG-IP":   ["bigipserver", "f5_cspm", "ts01"],
    "ModSecurity": ["mod_security", "NOYB"],
    "Barracuda":   ["barra_counter_session", "barracuda_"],
}

CDN_SIGNATURES: Dict[str, List[str]] = {
    "Cloudflare":     ["cf-cache-status", "cf-ray"],
    "Fastly":         ["x-served-by", "x-cache-hits", "fastly-"],
    "AWS CloudFront": ["x-amz-cf-pop", "x-amz-cf-id"],
    "Akamai":         ["x-check-cacheable", "x-akamai"],
    "Vercel":         ["x-vercel-cache", "x-vercel-id"],
    "Netlify":        ["x-nf-request-id", "netlify"],
}

SECURITY_HEADERS: List[str] = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]

# Keywords that make a JS variable name interesting for bug hunting
JS_SECRET_KEYWORDS: List[str] = [
    "key", "token", "secret", "api", "auth", "password", "pass", "pwd",
    "url", "endpoint", "config", "client_id", "client_secret", "access",
    "private", "credential", "webhook", "signing", "bearer", "jwt",
]

# ── Compiled regexes (module-level, built ONCE) ───────────────────────────────

# Email — avoids false positives on filenames like foo@2x.png
RE_EMAIL = re.compile(
    r'\b[a-zA-Z0-9._%+\-]{1,64}@(?:[a-zA-Z0-9\-]{1,63}\.){1,8}[a-zA-Z]{2,10}\b'
)

# Phone — international-aware, min 7 digits after stripping non-digits
RE_PHONE = re.compile(
    r'(?<!\d)(?:\+?(?:1|44|61|49|33|81|86|91)[\s.\-]?)?'
    r'(?:\(?\d{3}\)?[\s.\-]?)?\d{3}[\s.\-]?\d{4}(?!\d)'
)

RE_COMMENT = re.compile(r'<!--(.*?)-->', re.DOTALL)

# API routes: /api/*, /v1/*, /graphql, /rest/*, /rpc, /webhook
RE_API = re.compile(
    r'''["'](?:https?://[^"']{0,80})?(/(?:api|v\d+|graphql|rest|gql|rpc|endpoint|webhook)[^"'\s<>]{0,100})["']'''
)

# JS variable assignments whose names suggest secrets
RE_JS_VAR = re.compile(
    r'(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*["\'`]([^"\'`\n]{8,200})["\' `]'
)

# Hidden inputs — often contain CSRF tokens, nonces, internal IDs
RE_HIDDEN_INPUT = re.compile(
    r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\'][^>]*value=["\']([^"\']*)["\']',
    re.IGNORECASE,
)

# Source-map references (can expose compiled source paths)
RE_SOURCEMAP = re.compile(r'//[#@]\s*sourceMappingURL=\s*(\S+)')

# Hardcoded cloud / service API keys
RE_HARDCODED_SECRET = re.compile(
    r'(?:'
    r'AKIA[0-9A-Z]{16}'           # AWS access key ID
    r'|AIza[0-9A-Za-z\-_]{35}'   # Google API key
    r'|ghp_[0-9A-Za-z]{36}'      # GitHub personal access token
    r'|ghs_[0-9A-Za-z]{36}'      # GitHub service token
    r'|sk-[a-zA-Z0-9]{20,}'      # OpenAI-style secret key
    r'|eyJ[a-zA-Z0-9\-_]{20,}\.[a-zA-Z0-9\-_]{20,}'  # JWT
    r')'
)

# Extension blocklist — skip these content types entirely
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".mov", ".pdf", ".zip", ".gz",
    ".tar", ".exe", ".dmg", ".apk",
}
