"""
modules/stealth.py
WAF evasion layer:
  - StealthHeaders  : generates browser-realistic request headers
  - DomainRateLimiter: per-domain adaptive delay with backoff on 429/403/WAF signals
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

from .constants import (
    USER_AGENTS,
    SEC_CH_UA_MAP,
    ACCEPT_HEADERS,
    ACCEPT_LANG_HEADERS,
    WAF_BLOCK_BODY_PHRASES,
)

logger = logging.getLogger("CREEPER.stealth")


# ─── Header factory ───────────────────────────────────────────────────────────

class StealthHeaders:
    """
    Builds per-request HTTP headers that look like a real browser.

    - Picks a random UA and derives matching Sec-CH-UA / platform hints
    - Randomises Accept / Accept-Language / Cache-Control / Sec-Fetch-Site
    - Merges caller-supplied custom headers last (so session cookies survive)
    """

    def __init__(self, custom_headers: Optional[Dict[str, str]] = None):
        self._custom = custom_headers or {}

    def build(self, url: str) -> Dict[str, str]:
        ua       = random.choice(USER_AGENTS)
        is_mobile = any(kw in ua for kw in ("Mobile", "iPhone", "Android"))

        sec_ch_ua = ""
        for key, val in SEC_CH_UA_MAP.items():
            if key in ua:
                sec_ch_ua = val
                break

        platform = (
            '"Android"'  if "Android"   in ua else
            '"iOS"'      if "iPhone"    in ua else
            '"macOS"'    if "Macintosh" in ua else
            '"Windows"'
        )

        headers: Dict[str, str] = {
            "User-Agent":                ua,
            "Accept":                    random.choice(ACCEPT_HEADERS),
            "Accept-Language":           random.choice(ACCEPT_LANG_HEADERS),
            "Accept-Encoding":           "gzip, deflate",
            "Connection":                "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest":            "document",
            "Sec-Fetch-Mode":            "navigate",
            "Sec-Fetch-Site":            random.choice(["none", "same-origin", "cross-site"]),
            "Sec-Fetch-User":            "?1",
            "Cache-Control":             random.choice(["max-age=0", "no-cache"]),
        }

        # Chrome-specific client hints — only inject for Chrome/Edge UAs
        if "Chrome" in ua and sec_ch_ua:
            headers["Sec-CH-UA"]          = sec_ch_ua
            headers["Sec-CH-UA-Mobile"]   = "?1" if is_mobile else "?0"
            headers["Sec-CH-UA-Platform"] = platform

        # Caller-supplied headers (session cookies, auth tokens, etc.) go last
        headers.update(self._custom)
        return headers


def detect_waf_block(html: str) -> bool:
    """Return True if the response body contains WAF challenge / block phrases."""
    lower = html.lower()
    return any(phrase in lower for phrase in WAF_BLOCK_BODY_PHRASES)


# ─── Per-domain adaptive rate limiter ─────────────────────────────────────────

class DomainRateLimiter:
    """
    Tracks last-request time and backoff multiplier per domain.

    Usage:
        await limiter.wait(url)          # call BEFORE sending the request
        limiter.signal_block(url)        # call when WAF/429 detected
        limiter.signal_ok(url)           # call on clean 2xx/3xx response
    """

    def __init__(self, base_delay: Tuple[float, float] = (1.0, 3.0)):
        self._min, self._max = base_delay
        self._backoff:  Dict[str, float] = {}   # domain → current multiplier
        self._last_req: Dict[str, float] = {}   # domain → monotonic timestamp
        self._lock = asyncio.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    async def wait(self, url: str) -> None:
        """Sleep the right amount before issuing a request to this URL's domain."""
        domain = self._domain(url)
        async with self._lock:
            mult      = self._backoff.get(domain, 1.0)
            delay     = random.uniform(self._min * mult, self._max * mult)
            elapsed   = time.monotonic() - self._last_req.get(domain, 0.0)
            wait_time = delay - elapsed
        if wait_time > 0:
            await asyncio.sleep(wait_time)
        async with self._lock:
            self._last_req[domain] = time.monotonic()

    def signal_block(self, url: str) -> None:
        """Double+ the backoff for this domain — WAF or rate-limit detected."""
        domain  = self._domain(url)
        current = self._backoff.get(domain, 1.0)
        new_val = min(current * 2.5, 40.0)
        self._backoff[domain] = new_val
        logger.info("[stealth] WAF/block signal on %s → backoff ×%.1f", domain, new_val)

    def signal_ok(self, url: str) -> None:
        """Gently reduce backoff after a clean response."""
        domain  = self._domain(url)
        current = self._backoff.get(domain, 1.0)
        self._backoff[domain] = max(1.0, current * 0.85)

    def current_multiplier(self, url: str) -> float:
        return self._backoff.get(self._domain(url), 1.0)

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _domain(url: str) -> str:
        return urlparse(url).netloc
