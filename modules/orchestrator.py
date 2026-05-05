"""
modules/orchestrator.py
AsyncOSINTScraper — the public API of CREEPER.

Wires together:
  StealthHeaders + DomainRateLimiter  (stealth.py)
  RegexEngine                         (regex_engine.py)
  Spider                              (spider.py)
  BFSCrawler                          (bfs.py)
  build_report                        (reporter.py)
  export                              (exporter.py)

Usage (sync wrapper):
    scraper = AsyncOSINTScraper(concurrency=5, delay_range=(1.0, 3.0))
    report  = scraper.scrape("https://target.com", max_depth=2, max_pages=80)

Usage (async):
    async with aiohttp.ClientSession(...) as session:
        report = await scraper.run(session, start_url, ...)
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, List, Optional, Tuple

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector

from .bfs import BFSCrawler
from .exporter import export
from .regex_engine import RegexEngine
from .reporter import build_report
from .spider import Spider
from .stealth import DomainRateLimiter, StealthHeaders
from .ninja import NinjaStealth

# Optional Playwright
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

logger = logging.getLogger("CREEPER.orchestrator")


class AsyncOSINTScraper:
    """
    Public-facing scraper class.

    Parameters
    ----------
    concurrency     : max simultaneous in-flight requests (capped at 20)
    delay_range     : (min_s, max_s) per-domain random delay between requests
    timeout         : per-request timeout in seconds
    use_playwright  : re-render JS-heavy pages with headless Chromium
    playwright_pages: max concurrent Playwright pages
    respect_robots  : honour robots.txt Disallow rules
    verify_ssl      : validate TLS certificates
    regex_patterns  : list of Python regex strings to hunt for on pages
    regex_match_only: if True, only store pages where ≥1 pattern fired
    custom_headers  : extra headers merged into every request (cookies, auth)
    """

    def __init__(
        self,
        concurrency:      int                        = 5,
        delay_range:      Tuple[float, float]        = (1.0, 3.0),
        timeout:          int                        = 20,
        use_playwright:   bool                       = False,
        playwright_pages: int                        = 2,
        respect_robots:   bool                       = True,
        verify_ssl:       bool                       = True,
        regex_patterns:   Optional[List[str]]        = None,
        regex_match_only: bool                       = False,
        custom_headers:   Optional[Dict[str, str]]   = None,
        proxies:          Optional[List[str]]        = None,
        ninja_mode:       bool                       = False,
    ):
        self.concurrency      = min(concurrency, 20)
        self.delay_range      = delay_range
        self.timeout          = ClientTimeout(total=timeout, connect=10)
        self.use_playwright   = use_playwright and PLAYWRIGHT_AVAILABLE
        self.playwright_pages = playwright_pages
        self.respect_robots   = respect_robots
        self.verify_ssl       = verify_ssl
        self.regex_match_only = regex_match_only
        self.custom_headers   = custom_headers or {}
        
        self.ninja = NinjaStealth(proxies=proxies, use_ninja_mode=ninja_mode)

        self.regex_engine = RegexEngine(regex_patterns or [])

    # ── Sync wrapper (CLI / server entry point) ───────────────────────────────

    def scrape(
        self,
        start_url:      str,
        max_depth:      int          = 2,
        max_pages:      int          = 50,
        output_dir:     str          = ".",
        export_formats: List[str]    = ("json",),
    ) -> Dict:
        """Blocking wrapper — runs the async engine in a new event loop."""
        return asyncio.run(
            self._run(start_url, max_depth, max_pages, output_dir, export_formats)
        )

    # ── Async engine ──────────────────────────────────────────────────────────

    async def _run(
        self,
        start_url:      str,
        max_depth:      int,
        max_pages:      int,
        output_dir:     str,
        export_formats: List[str],
    ) -> Dict:
        semaphore   = asyncio.Semaphore(self.concurrency)
        rate_lim    = DomainRateLimiter(self.delay_range)
        stealth_hdr = StealthHeaders(self.custom_headers)

        connector = TCPConnector(
            limit=self.concurrency * 3,
            limit_per_host=min(self.concurrency, 6),
            ssl=self.verify_ssl,
            ttl_dns_cache=600,
            use_dns_cache=True,
            enable_cleanup_closed=True,
        )

        pw_browser = None
        pw_sem     = None

        async with ClientSession(
            connector=connector,
            timeout=self.timeout,
            headers={"Connection": "keep-alive"},
        ) as session:

            # Optional Playwright setup
            if self.use_playwright:
                try:
                    pw         = await async_playwright().start()
                    pw_browser = await pw.chromium.launch(headless=True)
                    pw_sem     = asyncio.Semaphore(self.playwright_pages)
                except Exception as exc:
                    logger.warning("Playwright init failed: %s — falling back to aiohttp", exc)

            spider = Spider(
                session=session,
                semaphore=semaphore,
                stealth_headers=stealth_hdr,
                rate_limiter=rate_lim,
                regex_engine=self.regex_engine,
                verify_ssl=self.verify_ssl,
                regex_match_only=self.regex_match_only,
                use_playwright=self.use_playwright,
                playwright_sem=pw_sem,
                playwright_browser=pw_browser,
                custom_headers=self.custom_headers,
                ninja=self.ninja,
            )

            if self.respect_robots:
                await spider.fetch_robots(start_url)

            crawler = BFSCrawler(spider, concurrency=self.concurrency)
            await crawler.run(start_url, max_depth, max_pages)

            if pw_browser:
                await pw_browser.close()

        report = build_report(
            start_url=start_url,
            results=spider.results,
            regex_patterns=self.regex_engine.raw_patterns,
            regex_errors=self.regex_engine.errors,
        )
        export(report, output_dir, export_formats)
        return report
