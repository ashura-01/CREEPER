"""
modules/js_parser.py
Fetches and deep-parses JavaScript files for endpoints, secrets, and paths.
This is the #1 thing Katana does that CREEPER was missing.

Katana's approach:
  1. Collect all <script src=...> from every HTML page
  2. Fetch each .js file
  3. Run multiple extraction passes on the raw JS text
  4. Also follow sourceMappingURL -> .map files -> original source paths

We do all of that here.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp import ClientSession, ClientTimeout

logger = logging.getLogger("CREEPER.js_parser")

# ── Compiled patterns (built once) ────────────────────────────────────────────

# Absolute URLs embedded in JS
_RE_ABS_URL = re.compile(
    r'''["'`](https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{10,300})["'`]'''
)

# Relative paths that look like API/page routes
_RE_REL_PATH = re.compile(
    r'''["'`](/[a-zA-Z0-9/_\-.]{2,120}(?:\?[a-zA-Z0-9=&_%\-.]{0,80})?)["'`]'''
)

# fetch() / axios calls
_RE_FETCH = re.compile(
    r'''(?:fetch|axios\.(?:get|post|put|patch|delete|head|options|request))\s*\(\s*["'`]([^"'`\s]{4,200})["'`]''',
    re.IGNORECASE,
)

# XMLHttpRequest open()
_RE_XHR = re.compile(
    r'''\.open\s*\(\s*["'`][A-Z]{3,7}["'`]\s*,\s*["'`]([^"'`\s]{4,200})["'`]''',
    re.IGNORECASE,
)

# Template literal paths: `/api/${version}/users`
_RE_TMPL = re.compile(
    r'''`(/[a-zA-Z0-9/_\-.${}]{4,120})`'''
)

# Object property URLs: { url: "/api/v1/...", endpoint: "..." }
_RE_OBJ_URL = re.compile(
    r'''(?:url|endpoint|path|route|href|action|src|api)\s*[:=]\s*["'`](/[a-zA-Z0-9/_\-.?=&]{3,100})["'`]''',
    re.IGNORECASE,
)

# Next.js data: __NEXT_DATA__ JSON blob
_RE_NEXT_DATA = re.compile(r'__NEXT_DATA__\s*=\s*(\{.{20,8000}?\})\s*(?:</script>|;)', re.DOTALL)

# Nuxt state blob
_RE_NUXT_DATA = re.compile(r'__NUXT__\s*=\s*(\{.{20,8000}?\})', re.DOTALL)

# WordPress REST API nonce / root URL
_RE_WP_REST = re.compile(r'"root"\s*:\s*"(https?://[^"]{10,200})"')

# sourceMappingURL
_RE_SOURCEMAP = re.compile(r'//[#@]\s*sourceMappingURL=\s*(\S+)')

# ── Secrets patterns (much wider than before) ─────────────────────────────────

SECRET_PATTERNS: List[tuple] = [
    # AWS
    (r'AKIA[0-9A-Z]{16}',                          "AWS Access Key ID"),
    (r'(?:aws_secret|AWS_SECRET)[^=\n]*=\s*["\']?([A-Za-z0-9/+]{40})',  "AWS Secret Key"),
    # Google
    (r'AIza[0-9A-Za-z\-_]{35}',                   "Google API Key"),
    (r'ya29\.[0-9A-Za-z\-_]{68,}',                "Google OAuth Token"),
    # GitHub
    (r'gh[pousr]_[0-9A-Za-z]{36,}',               "GitHub Token"),
    (r'github_pat_[0-9A-Za-z_]{82}',              "GitHub Fine-grained PAT"),
    # Stripe
    (r'(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}', "Stripe API Key"),
    (r'rk_(?:live|test)_[0-9a-zA-Z]{24,}',        "Stripe Restricted Key"),
    # Slack
    (r'xox[baprs]-[0-9A-Za-z\-]{10,}',            "Slack Token"),
    (r'https://hooks\.slack\.com/services/[A-Z0-9/]{40,}', "Slack Webhook"),
    # Twilio
    (r'AC[a-z0-9]{32}',                            "Twilio Account SID"),
    (r'SK[a-z0-9]{32}',                            "Twilio API Key"),
    # SendGrid
    (r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}', "SendGrid API Key"),
    # Mailgun
    (r'key-[0-9a-zA-Z]{32}',                      "Mailgun API Key"),
    # Azure
    (r'[Aa]z(?:ure)?[_\-]?(?:storage|key|secret)[^=\n]*=\s*["\']?([A-Za-z0-9+/]{43}=)', "Azure Storage Key"),
    # HubSpot
    (r'(?:hubspot|hs)[_\-]?(?:api[_\-]?key|token)[^=\n]*=\s*["\']?([a-z0-9\-]{36})', "HubSpot API Key"),
    # Shopify
    (r'shpss_[0-9a-fA-F]{32}',                    "Shopify Shared Secret"),
    (r'shpat_[0-9a-fA-F]{32}',                    "Shopify Access Token"),
    # Square
    (r'sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',        "Square API Key"),
    # PayPal / Braintree
    (r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}', "PayPal Braintree Token"),
    # Heroku
    (r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', "UUID / Heroku API Key"),
    # Private keys
    (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "Private Key Header"),
    # Connection strings
    (r'(?:mysql|postgres|postgresql|mongodb|redis|mssql)://[^\s"\'<>]{10,200}', "DB Connection String"),
    # Generic high-entropy secrets
    (r'(?:password|passwd|secret|api_?key|auth_?token|access_?token)\s*[:=]\s*["\']([^"\']{12,})["\']', "Generic Secret"),
    # JWT
    (r'eyJ[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}\.[A-Za-z0-9\-_]{20,}', "JWT Token"),
    # Firebase
    (r'AIza[0-9A-Za-z\-_]{35}',                   "Firebase API Key"),
    (r'"databaseURL"\s*:\s*"(https://[^.]+\.firebaseio\.com)"', "Firebase DB URL"),
    # OpenAI / Anthropic style
    (r'sk-[a-zA-Z0-9]{20,}',                      "API Secret Key (sk-)"),
    (r'sk-ant-[a-zA-Z0-9\-_]{40,}',               "Anthropic API Key"),
]

_COMPILED_SECRETS = [(re.compile(pat), name) for pat, name in SECRET_PATTERNS]

STATIC_EXTS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".mov", ".pdf", ".zip", ".gz",
    ".tar", ".exe", ".dmg", ".apk", ".bin",
})


@dataclass
class JSParseResult:
    js_url:        str
    endpoints:     List[str]  = field(default_factory=list)
    secrets:       List[str]  = field(default_factory=list)
    subdomains:    List[str]  = field(default_factory=list)
    sourcemaps:    List[str]  = field(default_factory=list)
    framework_hints: List[str] = field(default_factory=list)
    size_bytes:    int        = 0
    error:         str        = ""


def _is_likely_endpoint(path: str) -> bool:
    """Filter out obvious false positives from path extraction."""
    p = path.split("?")[0].lower()
    # Skip static assets
    if any(p.endswith(ext) for ext in STATIC_EXTS):
        return False
    # Skip very short paths
    if len(p) < 3:
        return False
    # Skip version strings like /1.2.3/
    if re.match(r'^/\d+\.\d+', p):
        return False
    return True


def parse_js_text(js_text: str, js_url: str, base_domain: str) -> JSParseResult:
    """
    Extract all recon-relevant data from a JS file's text content.
    Called both on fetched .js files and inline <script> content.
    """
    result = JSParseResult(js_url=js_url, size_bytes=len(js_text.encode()))
    parsed_base = urlparse(js_url)
    origin = f"{parsed_base.scheme}://{parsed_base.netloc}"
    bare_domain = base_domain.lower().removeprefix("www.")

    endpoints: Set[str] = set()
    secrets:   List[str] = []

    # ── Endpoint extraction ───────────────────────────────────────────────────

    # Absolute URLs
    for m in _RE_ABS_URL.finditer(js_text):
        url = m.group(1)
        u = urlparse(url)
        if u.netloc and bare_domain in u.netloc:
            endpoints.add(url)

    # fetch / axios
    for m in _RE_FETCH.finditer(js_text):
        path = m.group(1)
        if path.startswith("http"):
            endpoints.add(path)
        elif path.startswith("/"):
            endpoints.add(origin + path)

    # XHR
    for m in _RE_XHR.finditer(js_text):
        path = m.group(1)
        if path.startswith("http"):
            endpoints.add(path)
        elif path.startswith("/"):
            endpoints.add(origin + path)

    # Relative paths with quality filter
    for m in _RE_REL_PATH.finditer(js_text):
        path = m.group(1)
        if _is_likely_endpoint(path):
            endpoints.add(origin + path)

    # Template literals
    for m in _RE_TMPL.finditer(js_text):
        path = m.group(1)
        if _is_likely_endpoint(path.replace("${", "").replace("}", "")):
            endpoints.add(origin + path.split("$")[0] + "*")

    # Object property URLs
    for m in _RE_OBJ_URL.finditer(js_text):
        path = m.group(1)
        if _is_likely_endpoint(path):
            endpoints.add(origin + path)

    # ── Framework-specific data ───────────────────────────────────────────────

    # Next.js __NEXT_DATA__
    for m in _RE_NEXT_DATA.finditer(js_text):
        try:
            data = json.loads(m.group(1))
            result.framework_hints.append("Next.js")
            # Extract buildId and props URLs
            if "buildId" in data:
                build_id = data["buildId"]
                endpoints.add(f"{origin}/_next/data/{build_id}/index.json")
            # Walk props for URLs
            _walk_json_for_urls(data, origin, endpoints)
        except Exception:
            pass

    # Nuxt
    for m in _RE_NUXT_DATA.finditer(js_text):
        result.framework_hints.append("Nuxt.js")
        try:
            data = json.loads(m.group(1))
            _walk_json_for_urls(data, origin, endpoints)
        except Exception:
            pass

    # WP REST root
    for m in _RE_WP_REST.finditer(js_text):
        rest_root = m.group(1)
        endpoints.add(rest_root)
        endpoints.add(rest_root + "wp/v2/posts")
        result.framework_hints.append("WordPress REST")

    # ── Source maps ───────────────────────────────────────────────────────────
    for m in _RE_SOURCEMAP.finditer(js_text):
        ref = m.group(1).strip()
        if ref.startswith("http"):
            result.sourcemaps.append(ref)
        elif not ref.startswith("data:"):
            full = urljoin(js_url, ref)
            result.sourcemaps.append(full)

    # ── Secrets ───────────────────────────────────────────────────────────────
    for pattern, name in _COMPILED_SECRETS:
        for m in pattern.finditer(js_text):
            val = m.group(0)[:100]
            entry = f"[{name}] {val}"
            if entry not in secrets:
                secrets.append(entry)

    # ── Subdomains ────────────────────────────────────────────────────────────
    root = ".".join(bare_domain.split(".")[-2:])
    sub_re = re.compile(
        r'([a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)*\.' + re.escape(root) + r')',
        re.IGNORECASE,
    )
    for m in sub_re.finditer(js_text):
        sub = m.group(1).lower()
        if sub not in (bare_domain, f"www.{bare_domain}"):
            result.subdomains.append(sub)

    # Filter and deduplicate endpoints
    result.endpoints = list(dict.fromkeys(
        e for e in endpoints if _is_likely_endpoint(urlparse(e).path or e)
    ))[:150]
    result.secrets   = list(dict.fromkeys(secrets))[:50]
    result.subdomains = list(dict.fromkeys(result.subdomains))[:40]
    return result


def _walk_json_for_urls(obj, origin: str, endpoints: Set[str], depth: int = 0) -> None:
    """Recursively walk a JSON object looking for URL-shaped strings."""
    if depth > 6:
        return
    if isinstance(obj, dict):
        for v in obj.values():
            _walk_json_for_urls(v, origin, endpoints, depth + 1)
    elif isinstance(obj, list):
        for item in obj[:20]:
            _walk_json_for_urls(item, origin, endpoints, depth + 1)
    elif isinstance(obj, str) and 4 < len(obj) < 200:
        if obj.startswith("/") and _is_likely_endpoint(obj):
            endpoints.add(origin + obj)
        elif obj.startswith("http") and origin in obj:
            endpoints.add(obj)


async def fetch_and_parse_js(
    js_urls:     List[str],
    session:     ClientSession,
    semaphore:   asyncio.Semaphore,
    base_domain: str,
    timeout:     int = 12,
    max_size:    int = 3_000_000,   # 3 MB cap — minified bundles can be huge
) -> List[JSParseResult]:
    """
    Fetch a list of JS URLs concurrently and parse each for recon data.
    Returns one JSParseResult per successfully fetched file.
    """
    to      = ClientTimeout(total=timeout, connect=5)
    results = []
    js_sem  = asyncio.Semaphore(8)   # max 8 concurrent JS fetches

    async def fetch_one(url: str) -> Optional[JSParseResult]:
        async with js_sem:
            async with semaphore:
                try:
                    async with session.get(
                        url,
                        timeout=to,
                        headers={"Accept": "*/*", "Referer": url},
                        allow_redirects=True,
                        ssl=False,
                    ) as resp:
                        if resp.status != 200:
                            return None
                        ctype = resp.headers.get("content-type", "")
                        if "html" in ctype and "javascript" not in ctype:
                            return None  # got an HTML error page
                        # Read up to max_size
                        chunks = []
                        size   = 0
                        async for chunk in resp.content.iter_chunked(65536):
                            size += len(chunk)
                            chunks.append(chunk)
                            if size >= max_size:
                                logger.debug("JS size cap hit: %s (%d bytes)", url, size)
                                break
                        text = b"".join(chunks).decode("utf-8", errors="replace")
                        parsed_url = urlparse(url)
                        bd = parsed_url.netloc.lower().removeprefix("www.")
                        r  = parse_js_text(text, url, bd if bd else base_domain)
                        logger.debug(
                            "JS parsed: %s → %d endpoints, %d secrets",
                            url, len(r.endpoints), len(r.secrets),
                        )
                        return r
                except Exception as exc:
                    logger.debug("JS fetch failed %s: %s", url, exc)
                    return None

    tasks = [fetch_one(url) for url in js_urls]
    raw   = await asyncio.gather(*tasks)
    return [r for r in raw if r is not None]


async def fetch_sourcemap(
    map_url:  str,
    session:  ClientSession,
    timeout:  int = 8,
) -> List[str]:
    """
    Fetch a .map file and extract the original source file paths from it.
    Source maps expose the full compiled source tree — very valuable for
    understanding an app's internal structure.
    """
    to = ClientTimeout(total=timeout, connect=4)
    try:
        async with session.get(map_url, timeout=to, ssl=False) as resp:
            if resp.status != 200:
                return []
            text = await resp.text(errors="replace")
            data = json.loads(text)
            sources = data.get("sources", [])
            return [s for s in sources if isinstance(s, str)][:200]
    except Exception as exc:
        logger.debug("Sourcemap fetch failed %s: %s", map_url, exc)
        return []