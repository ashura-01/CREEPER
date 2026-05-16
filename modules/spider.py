"""
modules/spider.py
The page-fetching and parsing heart of CREEPER.
Spider.fetch_page() handles one URL end-to-end:
  stealth headers → aiohttp GET → WAF detection → HTML parse → recon extract
  → optional Playwright re-render.

BFSCrawler calls spider.fetch_page(); the orchestrating AsyncOSINTScraper
owns the session and wires everything together.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import asdict
from typing import Dict, List, Optional, Set, Tuple

import aiohttp
from aiohttp import ClientSession, ClientTimeout
from bs4 import BeautifulSoup

from .constants import WAF_BLOCK_STATUSES
from .extractor import (
    extract_api_endpoints,
    extract_comments,
    extract_emails,
    extract_forms,
    extract_js_vars,
    extract_links,
    extract_meta,
    extract_parameters,
    extract_phones,
    extract_subdomains,
    fingerprint_tech,
    needs_js_render,
)
from .models import ScrapedPage, JSFile
from .js_parser import fetch_and_parse_js, parse_js_text, fetch_sourcemap
from .regex_engine import RegexEngine
from .stealth import DomainRateLimiter, StealthHeaders, detect_waf_block
from .ninja import NinjaStealth

# Optional Playwright
try:
    from playwright.async_api import Browser, Page as PlaywrightPage, async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

logger = logging.getLogger("CREEPER.spider")


class Spider:
    """
    Fetches and parses one page at a time.

    Owns:
      - visited   set (read/written by BFSCrawler too)
      - results   list
      - disallowed set (populated by robots.txt fetch)
    """

    def __init__(
        self,
        session:         ClientSession,
        semaphore:       asyncio.Semaphore,
        stealth_headers: StealthHeaders,
        rate_limiter:    DomainRateLimiter,
        regex_engine:    RegexEngine,
        verify_ssl:      bool = True,
        regex_match_only: bool = False,
        use_playwright:  bool = False,
        playwright_sem:  Optional[asyncio.Semaphore] = None,
        playwright_browser: Optional["Browser"] = None,
        custom_headers:  Optional[Dict[str, str]] = None,
        ninja:           Optional[NinjaStealth] = None,
    ):
        self._session     = session
        self._sem         = semaphore
        self._headers     = stealth_headers
        self._rate        = rate_limiter
        self._ssl         = verify_ssl
        self._custom      = custom_headers or {}
        self.ninja        = ninja or NinjaStealth()

        self.regex_engine    = regex_engine
        self.regex_match_only = regex_match_only

        self._use_pw     = use_playwright and PLAYWRIGHT_AVAILABLE
        self._pw_sem     = playwright_sem
        self._pw_browser = playwright_browser

        # Shared state written by BFSCrawler
        self.visited:    Set[str]        = set()
        self.results:    List[ScrapedPage] = []
        self.disallowed: Set[str]        = set()
        self.js_results: List[JSFile]      = []   # parsed JS files
        self._js_seen:   Set[str]          = set() # already-fetched JS URLs

    # ── Robots.txt ────────────────────────────────────────────────────────────

    async def fetch_robots(self, start_url: str) -> None:
        from urllib.parse import urlparse
        from .constants import USER_AGENTS
        parsed     = urlparse(start_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            async with self._session.get(
                robots_url,
                timeout=ClientTimeout(total=8),
                headers={"User-Agent": random.choice(USER_AGENTS)},
                ssl=self._ssl,
            ) as resp:
                if resp.status == 200:
                    text     = await resp.text()
                    in_block = False
                    for line in text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("user-agent:"):
                            agent    = line.split(":", 1)[1].strip()
                            in_block = agent in ("*", "CREEPER")
                        elif in_block and line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path:
                                self.disallowed.add(
                                    f"{parsed.scheme}://{parsed.netloc}{path}"
                                )
        except Exception:
            pass

    def is_disallowed(self, url: str) -> bool:
        return any(url.startswith(d) for d in self.disallowed)

    # ── Core fetch ────────────────────────────────────────────────────────────

    async def fetch_page(self, url: str) -> Optional[ScrapedPage]:
        """
        Stealth-fetch one URL.
        - Respects per-domain rate limiting (waits BEFORE acquiring semaphore)
        - Retries once on transient network errors
        - Detects WAF blocks by status code and body content
        - Optionally re-renders with Playwright if page looks JS-heavy
        """
        await self._rate.wait(url)

        async with self._sem:
            headers = self._headers.build(url)
            for attempt in range(2):
                try:
                    t0 = time.monotonic()
                    async with self._session.get(
                        url,
                        headers=headers,
                        allow_redirects=True,
                        max_redirects=5,
                        ssl=self._ssl,
                        **self.ninja.get_aiohttp_kwargs()
                    ) as resp:
                        elapsed = (time.monotonic() - t0) * 1000
                        status  = resp.status
                        ctype   = resp.headers.get("content-type", "")

                        logger.debug("HTTP %d  ctype=%r  url=%s", status, ctype, url)

                        # WAF / hard block
                        if status in WAF_BLOCK_STATUSES:
                            self._rate.signal_block(url)
                            if status == 429 and attempt == 0:
                                retry_after = int(resp.headers.get("retry-after", 12))
                                logger.info("[429] backing off %ds for %s", retry_after, url)
                                await asyncio.sleep(min(retry_after, 90))
                                continue
                            logger.warning("BLOCKED status=%d: %s", status, url)
                            return None

                        # Only parse HTML/text
                        if "text/html" not in ctype and "text/plain" not in ctype:
                            logger.debug("SKIP non-html ctype=%r: %s", ctype, url)
                            return None

                        html   = await resp.text(errors="replace")
                        r_hdrs = dict(resp.headers)
                        logger.debug("HTML len=%d final_url=%s", len(html), str(resp.url))

                        waf_body = detect_waf_block(html)
                        if waf_body:
                            logger.warning("WAF body block detected: %s", url)
                            self._rate.signal_block(url)

                        page = self._parse(str(resp.url), html, status, ctype, elapsed, r_hdrs)
                        page.waf_blocked = waf_body

                        logger.debug(
                            "PARSED links=%d emails=%d forms=%d: %s",
                            len(page.links), len(page.emails), len(page.forms), url
                        )

                        self._rate.signal_ok(url)

                        if self._use_pw and needs_js_render(html):
                            page = await self._playwright_render(url, page)

                        # Fetch and parse JS files found on this page
                        await self._parse_js_files(page)

                        return page

                except (
                    aiohttp.ServerDisconnectedError,
                    aiohttp.ClientConnectorError,
                    asyncio.TimeoutError,
                ) as exc:
                    if attempt == 0:
                        wait = random.uniform(1.5, 4.0)
                        logger.warning("Transient %s on %s, retry in %.1fs", type(exc).__name__, url, wait)
                        await asyncio.sleep(wait)
                    else:
                        logger.warning("FAILED after retry %s: %s", url, exc)
                        return None
                except Exception as exc:
                    logger.warning("EXCEPTION %s on %s: %s", type(exc).__name__, url, exc)
                    return None

            return None

    # ── HTML parse ────────────────────────────────────────────────────────────

    def _parse(
        self,
        url:     str,
        html:    str,
        status:  int,
        ctype:   str,
        elapsed: float,
        headers: Dict,
    ) -> ScrapedPage:
        from urllib.parse import urlparse as _up
        # Strip www. so subdomain extraction and link scoping stay consistent
        # regardless of whether the server redirected bare→www or vice-versa
        base_domain = _up(url).netloc.lower().removeprefix("www.")

        soup      = BeautifulSoup(html, "html.parser")
        title_tag = soup.find("title")
        title     = title_tag.get_text(strip=True) if title_tag else "No title"
        page_text = soup.get_text(separator=" ", strip=True)

        links, ext_links = extract_links(soup, url, base_domain)
        tech             = fingerprint_tech(html, soup, headers)

        # Regex matching
        regex_matches, matched_patterns = (
            self.regex_engine.match_page(page_text, html)
            if self.regex_engine.is_valid()
            else ([], [])
        )

        return ScrapedPage(
            url=url,
            title=title,
            status_code=status,
            content_type=ctype,
            text_preview=page_text[:500],
            response_time_ms=round(elapsed, 1),
            links=links,
            external_links=ext_links,
            emails=extract_emails(html),
            phones=extract_phones(html),
            forms=extract_forms(soup, url),
            scripts=[s.get("src", "") for s in soup.find_all("script") if s.get("src")],
            comments=extract_comments(html),
            meta=extract_meta(soup),
            subdomains=extract_subdomains(html, base_domain),
            api_endpoints=extract_api_endpoints(html, base_url=url),
            js_variables=extract_js_vars(html),
            parameters=[dict(p) for p in extract_parameters(soup, url, html)],
            js_files=[],
            sourcemaps=[],
            tech=tech,
            regex_matches=regex_matches,
            matched_patterns=matched_patterns,
        )

    # ── Playwright re-render ──────────────────────────────────────────────────

    async def _playwright_render(self, url: str, base_page: ScrapedPage) -> ScrapedPage:
        if not self._pw_browser or not self._pw_sem:
            return base_page

        async with self._pw_sem:
            try:
                from modules.constants import USER_AGENTS
                ctx  = await self._pw_browser.new_context(
                    user_agent=random.choice(USER_AGENTS),
                    ignore_https_errors=not self._ssl,
                    extra_http_headers=self._custom,
                )
                pw_page: PlaywrightPage = await ctx.new_page()
                
                # Apply Ninja stealth scripts
                await self.ninja.apply_playwright_stealth(pw_page)
                
                await pw_page.goto(url, wait_until="networkidle", timeout=28_000)
                html = await pw_page.content()
                await ctx.close()

                rendered = self._parse(
                    url, html,
                    base_page.status_code, base_page.content_type,
                    base_page.response_time_ms, {},
                )
                rendered.rendered = True
                return rendered

            except Exception as exc:
                logger.debug("Playwright failed for %s: %s", url, exc)
                return base_page


    # ── JS file fetching ──────────────────────────────────────────────────────

    async def _parse_js_files(self, page: ScrapedPage) -> None:
        """
        Fetch every external JS file referenced on a page, parse each for
        endpoints/secrets/subdomains, and merge findings back into the page
        and the global js_results list.
        """
        from urllib.parse import urljoin, urlparse as _up
        parsed = _up(page.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        base_domain = parsed.netloc.lower().removeprefix("www.")

        # Collect JS URLs: <script src>, plus any .js links we found
        js_urls = []
        for src in page.scripts:
            if not src:
                continue
            full = src if src.startswith("http") else urljoin(page.url, src)
            if full not in self._js_seen:
                self._js_seen.add(full)
                js_urls.append(full)

        # Also scan inline <script> content directly from the page HTML
        # (already done in extractor, but we re-run with the JS parser for
        #  richer extraction — fetch_and_parse_js handles external URLs only)

        if not js_urls:
            return

        logger.debug("Fetching %d JS files from %s", len(js_urls), page.url)
        js_results = await fetch_and_parse_js(
            js_urls=js_urls,
            session=self._session,
            semaphore=self._sem,
            base_domain=base_domain,
        )

        # Merge findings into the page and global state
        for r in js_results:
            page.api_endpoints = list(dict.fromkeys(
                page.api_endpoints + r.endpoints
            ))[:120]
            page.js_variables = list(dict.fromkeys(
                page.js_variables + r.secrets
            ))[:60]
            page.subdomains = list(dict.fromkeys(
                page.subdomains + r.subdomains
            ))[:60]
            page.sourcemaps = list(dict.fromkeys(
                page.sourcemaps + r.sourcemaps
            ))[:20]
            page.js_files.append(r.url)

            # Store full JS result globally
            self.js_results.append(r)

            # Follow sourcemaps — fetch and record original source paths
            for sm_url in r.sourcemaps[:3]:
                source_paths = await fetch_sourcemap(sm_url, self._session)
                if source_paths:
                    logger.info("Sourcemap %s → %d source files", sm_url, len(source_paths))
                    page.comments.append(
                        f"[SOURCEMAP] {sm_url} → {len(source_paths)} sources: "
                        + ", ".join(source_paths[:5])
                    )