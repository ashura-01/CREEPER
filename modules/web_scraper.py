"""
modules/web_scraper.py
CREEPER v3.0 — main orchestrator.

This module is intentionally thin: it wires together the specialised
sub-modules and provides the single public class AsyncOSINTScraper that
both scrape_cli.py and server.py import.

Sub-module responsibilities
───────────────────────────
  models.py       – dataclasses (ScrapedPage, TechFingerprint, RegexMatch)
  constants.py    – UA pool, header pools, compiled regexes, signatures
  regex_engine.py – user pattern compilation + page matching
  stealth.py      – StealthHeaders, DomainRateLimiter, detect_waf_block
  extractor.py    – all HTML/text recon extraction functions
  spider.py       – fetch_page(), robots.txt, Playwright re-render
  bfs.py          – BFSCrawler (concurrent breadth-first crawl)
  reporter.py     – build_report(), format_report() (Rich terminal)
  exporter.py     – export() dispatcher (JSON / CSV / SQLite)
  waf_detect.py   – WAF fingerprint analysis & bypass hint generation
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Dict, List, Optional, Tuple

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector

from .bfs       import BFSCrawler
from .exporter  import export
from .models    import ScrapedPage
from .regex_engine import RegexEngine
from .reporter  import build_report, format_report
from .spider    import Spider
from .stealth   import DomainRateLimiter, StealthHeaders
from .constants import USER_AGENTS

# Optional Playwright
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

logger = logging.getLogger("CREEPER.orchestrator")


class AsyncOSINTScraper:
    """
    Public entry point for CREEPER.

    Usage (programmatic)
    --------------------
        scraper = AsyncOSINTScraper(concurrency=8, delay_range=(1.5, 4.0))
        report  = scraper.scrape("https://target.example.com", max_depth=3)

    Usage (from CLI / server)
    -------------------------
        See scrape_cli.py and server.py.
    """

    def __init__(
        self,
        concurrency:      int                        = 5,
        delay_range:      Tuple[float, float]        = (1.5, 3.5),
        timeout:          int                        = 20,
        use_playwright:   bool                       = False,
        playwright_pages: int                        = 2,
        respect_robots:   bool                       = True,
        verify_ssl:       bool                       = True,
        regex_patterns:   Optional[List[str]]        = None,
        regex_match_only: bool                       = False,
        custom_headers:   Optional[Dict[str, str]]   = None,
    ):
        # Cap concurrency — more than ~15 workers on a single target
        # almost always triggers rate-limiting / WAF blocks.
        self.concurrency      = min(max(1, concurrency), 20)
        self.timeout          = ClientTimeout(total=timeout, connect=10)
        self.use_playwright   = use_playwright and PLAYWRIGHT_AVAILABLE
        self.playwright_pages = max(1, playwright_pages)
        self.respect_robots   = respect_robots
        self.verify_ssl       = verify_ssl
        self.regex_match_only = regex_match_only
        self.custom_headers   = custom_headers or {}

        self.regex_engine = RegexEngine(regex_patterns or [])
        self.rate_limiter = DomainRateLimiter(delay_range)
        self.stealth      = StealthHeaders(self.custom_headers)

    # ── Synchronous public wrapper ─────────────────────────────────────────────

    def scrape(
        self,
        start_url:      str,
        max_depth:      int        = 2,
        max_pages:      int        = 50,
        output_dir:     str        = ".",
        export_formats: List[str]  = ("json",),
    ) -> Dict:
        """Synchronous entry point — runs the async engine via asyncio.run()."""
        return asyncio.run(
            self._run(start_url, max_depth, max_pages, output_dir, list(export_formats))
        )

    # ── Async core ────────────────────────────────────────────────────────────

    async def _run(
        self,
        start_url:      str,
        max_depth:      int,
        max_pages:      int,
        output_dir:     str,
        export_formats: List[str],
    ) -> Dict:
        semaphore = asyncio.Semaphore(self.concurrency)

        # Per-host limit avoids slamming a single server with all workers.
        connector = TCPConnector(
            limit=self.concurrency * 3,
            limit_per_host=min(self.concurrency, 8),
            ssl=self.verify_ssl,
            ttl_dns_cache=600,
            use_dns_cache=True,
            enable_cleanup_closed=True,
        )

        async with ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers={"Connection": "keep-alive"},
        ) as session:

            # Optional Playwright browser
            pw_browser = None
            pw_sem     = None
            if self.use_playwright:
                pw_browser, pw_sem = await self._start_playwright()

            spider = Spider(
                session          = session,
                semaphore        = semaphore,
                stealth_headers  = self.stealth,
                rate_limiter     = self.rate_limiter,
                regex_engine     = self.regex_engine,
                verify_ssl       = self.verify_ssl,
                regex_match_only = self.regex_match_only,
                use_playwright   = self.use_playwright,
                playwright_sem   = pw_sem,
                playwright_browser = pw_browser,
                custom_headers   = self.custom_headers,
            )

            if self.respect_robots:
                await spider.fetch_robots(start_url)

            crawler = BFSCrawler(spider=spider, concurrency=self.concurrency)
            await crawler.run(start_url, max_depth, max_pages)

            if pw_browser:
                await pw_browser.close()

        report = build_report(
            start_url      = start_url,
            results        = spider.results,
            regex_patterns = self.regex_engine.raw_patterns,
            regex_errors   = self.regex_engine.errors,
        )
        export(report, output_dir, export_formats)
        return report

    # ── Playwright lifecycle ───────────────────────────────────────────────────

    async def _start_playwright(self):
        """Launch a headless Chromium browser; returns (browser, semaphore)."""
        if not PLAYWRIGHT_AVAILABLE:
            logger.warning("Playwright not installed — JS rendering disabled.")
            return None, None
        try:
            pw      = await async_playwright().start()
            browser = await pw.chromium.launch(headless=True)
            sem     = asyncio.Semaphore(self.playwright_pages)
            logger.info("Playwright browser launched (max %d concurrent pages).",
                        self.playwright_pages)
            return browser, sem
        except Exception as exc:
            logger.warning("Playwright failed to start: %s", exc)
            return None, None


# ── Convenience re-exports so old import paths keep working ───────────────────
# scrape_cli.py does:  from modules.web_scraper import AsyncOSINTScraper, format_scraper
format_scraper = format_report          # backward-compat alias
