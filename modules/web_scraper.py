"""
CREEPER/modules/web_scraper.py
Advanced Async OSINT Web Scraper — CREEPER
New feature: Regex Pattern Matching — returns URLs where page content matches any supplied regex.
"""

from __future__ import annotations

import asyncio
import csv
import json
import re
import sqlite3
import random
import time
import logging
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse
from pathlib import Path
from datetime import datetime

import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
)
from rich import box

# ─── Optional JS rendering (Playwright) ────────────────────────────────────────
try:
    from playwright.async_api import async_playwright, Browser, Page as PlaywrightPage

    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

console = Console()
logger = logging.getLogger("CREEPER.scraper")

# ─── Stealth User-Agent Pool ────────────────────────────────────────────────────
USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
]

ACCEPT_HEADERS: List[str] = [
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
]

# ─── Data Models ────────────────────────────────────────────────────────────────


@dataclass
class RegexMatch:
    """A single regex pattern match found on a page."""

    pattern: str  # the regex pattern string
    match_text: str  # the actual matched text (up to 300 chars)
    match_count: int  # how many times it matched on this page
    context: str  # surrounding text snippet for context


@dataclass
class TechFingerprint:
    server: str = ""
    powered_by: str = ""
    frameworks: List[str] = field(default_factory=list)
    cms: str = ""
    cdn: str = ""
    waf: str = ""
    cookies: List[str] = field(default_factory=list)
    security_headers: Dict[str, str] = field(default_factory=dict)
    missing_security_headers: List[str] = field(default_factory=list)


@dataclass
class ScrapedPage:
    url: str
    title: str
    status_code: int
    content_type: str
    text_preview: str
    response_time_ms: float = 0.0
    links: List[str] = field(default_factory=list)
    external_links: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)
    phones: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    meta: Dict[str, str] = field(default_factory=dict)
    social_links: List[str] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    js_variables: List[str] = field(default_factory=list)
    tech: TechFingerprint = field(default_factory=TechFingerprint)
    rendered: bool = False
    # ── NEW: Regex match results ──────────────────────────────────────────────
    regex_matches: List[RegexMatch] = field(default_factory=list)
    matched_patterns: List[str] = field(default_factory=list)  # which patterns fired


# ─── Built-in Regexes ──────────────────────────────────────────────────────────

RE_EMAIL = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
RE_PHONE = re.compile(r"(?:\+?1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)?\d{3}[\s.-]?\d{4}")
RE_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
RE_API = re.compile(
    r'["\'](?:https?://[^"\']+)?(/(?:api|v\d|graphql|rest|endpoint)[^\s"\']{0,80})["\']'
)
RE_JS_VAR = re.compile(r'(?:var|let|const)\s+(\w+)\s*=\s*["\']([^"\']{8,})["\']')

SOCIAL_PATTERNS = [
    "facebook.com",
    "twitter.com",
    "x.com",
    "linkedin.com",
    "instagram.com",
    "github.com",
    "youtube.com",
    "tiktok.com",
    "telegram.me",
    "t.me",
    "discord.gg",
]

SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]

CMS_SIGNATURES = {
    "WordPress": ["/wp-content/", "/wp-includes/", "wp-login.php"],
    "Joomla": ["/components/com_", "Joomla!", "/media/jui/"],
    "Drupal": ["Drupal.settings", "/sites/default/files/", "drupal.js"],
    "Shopify": ["cdn.shopify.com", "Shopify.theme", "/shopify/"],
    "Magento": ["Mage.Cookies", "/skin/frontend/", "magento"],
    "Django": ["csrfmiddlewaretoken", "__django"],
    "Laravel": ["laravel_session", "XSRF-TOKEN"],
    "React": ["__REACT_DEVTOOLS", "react-root", "_reactFiber"],
    "Vue.js": ["__vue__", "v-cloak", "data-v-"],
    "Next.js": ["__NEXT_DATA__", "_next/static"],
    "Nuxt.js": ["__NUXT__", "_nuxt/"],
    "Angular": ["ng-version", "ng-app", "angular.min.js"],
}

WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "__cfduid"],
    "AWS WAF": ["x-amzn-requestid", "x-amz-cf-id"],
    "Akamai": ["akamai", "x-akamai-request-id"],
    "Imperva": ["x-iinfo", "incap_ses", "visid_incap"],
    "Sucuri": ["x-sucuri-id", "sucuri-clientid"],
    "F5 BIG-IP": ["bigipserver", "f5_cspm"],
}

CDN_SIGNATURES = {
    "Cloudflare": ["cf-cache-status", "cf-ray"],
    "Fastly": ["x-served-by", "x-cache-hits"],
    "AWS CloudFront": ["x-amz-cf-pop", "x-amz-cf-id"],
    "Akamai": ["x-check-cacheable", "x-akamai"],
    "Vercel": ["x-vercel-cache", "x-vercel-id"],
}


# ─── Regex Pattern Engine ──────────────────────────────────────────────────────


class RegexEngine:
    """
    Compile and apply multiple user-supplied regex patterns against page content.
    Returns matches with context snippets.
    """

    def __init__(self, patterns: List[str], flags: int = re.IGNORECASE):
        self.raw_patterns = patterns
        self.compiled: List[Tuple[str, re.Pattern]] = []
        self.errors: List[str] = []

        for pat in patterns:
            pat = pat.strip()
            if not pat:
                continue
            try:
                self.compiled.append((pat, re.compile(pat, flags)))
            except re.error as e:
                self.errors.append(f"Invalid regex '{pat}': {e}")

    def match_page(self, text: str, html: str) -> Tuple[List[RegexMatch], List[str]]:
        """
        Run all compiled patterns against visible page text + raw HTML.
        Returns (list_of_RegexMatch, list_of_matched_pattern_strings).
        """
        matches: List[RegexMatch] = []
        fired_patterns: List[str] = []

        # Search both plain text and raw HTML so patterns can target either
        search_targets = [("text", text), ("html", html)]

        for pat_str, compiled in self.compiled:
            best_match = None
            total_count = 0

            for source_name, source in search_targets:
                found = list(compiled.finditer(source))
                if found:
                    total_count += len(found)
                    if best_match is None:
                        m = found[0]
                        # Build context: 80 chars before and after
                        start = max(0, m.start() - 80)
                        end = min(len(source), m.end() + 80)
                        context_raw = source[start:end]
                        # Strip HTML tags for readability if searching HTML
                        if source_name == "html":
                            context_raw = re.sub(r"<[^>]+>", " ", context_raw)
                            context_raw = re.sub(r"\s+", " ", context_raw).strip()
                        best_match = RegexMatch(
                            pattern=pat_str,
                            match_text=m.group(0)[:300],
                            match_count=total_count,
                            context=context_raw[:300],
                        )

            if best_match:
                best_match.match_count = total_count
                matches.append(best_match)
                fired_patterns.append(pat_str)

        return matches, fired_patterns

    def is_valid(self) -> bool:
        return len(self.compiled) > 0

    @property
    def pattern_count(self) -> int:
        return len(self.compiled)


# ─── Core Scraper ──────────────────────────────────────────────────────────────


class AsyncOSINTScraper:
    """
    Async-first OSINT web scraper with:
    - Multi-regex content matching → returns URLs where patterns matched
    - aiohttp concurrent crawling with BFS
    - Stealth (rotating UA, delays, header randomization)
    - Tech fingerprinting (CMS, WAF, CDN, frameworks)
    - Deep recon (emails, phones, API routes, JS vars, subdomains)
    - Optional Playwright JS rendering
    - Export to JSON / CSV / SQLite
    """

    def __init__(
        self,
        concurrency: int = 5,
        delay_range: Tuple[float, float] = (0.5, 2.0),
        timeout: int = 15,
        use_playwright: bool = False,
        playwright_pages: int = 3,
        respect_robots: bool = True,
        verify_ssl: bool = True,
        regex_patterns: Optional[List[str]] = None,
        regex_match_only: bool = False,  # if True, only return pages that matched a pattern
    ):
        self.concurrency = concurrency
        self.delay_range = delay_range
        self.timeout = ClientTimeout(total=timeout)
        self.use_playwright = use_playwright and PLAYWRIGHT_AVAILABLE
        self.playwright_pages = playwright_pages
        self.respect_robots = respect_robots
        self.verify_ssl = verify_ssl
        self.regex_match_only = regex_match_only

        # Build regex engine
        self.regex_engine = RegexEngine(regex_patterns or [])

        self.visited: Set[str] = set()
        self.results: List[ScrapedPage] = []
        self.disallowed: Set[str] = set()
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._playwright_browser: Optional["Browser"] = None
        self._playwright_sem: Optional[asyncio.Semaphore] = None

    # ── Public entry point ────────────────────────────────────────────────────

    def scrape(
        self,
        start_url: str,
        max_depth: int = 2,
        max_pages: int = 50,
        output_dir: str = ".",
        export_formats: List[str] = ("json",),
    ) -> Dict:
        """Synchronous wrapper — runs the async engine."""
        return asyncio.run(
            self._run(start_url, max_depth, max_pages, output_dir, export_formats)
        )

    async def _run(self, start_url, max_depth, max_pages, output_dir, export_formats):
        self._semaphore = asyncio.Semaphore(self.concurrency)

        connector = TCPConnector(
            limit=self.concurrency * 2,
            ssl=self.verify_ssl,
            ttl_dns_cache=300,
        )

        async with ClientSession(connector=connector, timeout=self.timeout) as session:
            self._session = session

            if self.respect_robots:
                await self._fetch_robots(start_url)

            if self.use_playwright:
                await self._start_playwright()
                self._playwright_sem = asyncio.Semaphore(self.playwright_pages)

            await self._crawl_bfs(start_url, max_depth, max_pages)

            if self._playwright_browser:
                await self._playwright_browser.close()

        report = self._build_report(start_url)
        self._export(report, output_dir, export_formats)
        return report

    # ── BFS Crawler ───────────────────────────────────────────────────────────

    async def _crawl_bfs(self, start_url: str, max_depth: int, max_pages: int):
        base_domain = urlparse(start_url).netloc
        queue: asyncio.Queue = asyncio.Queue()
        await queue.put((start_url, 0))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Crawling...", total=max_pages)

            async def worker():
                while True:
                    try:
                        url, depth = queue.get_nowait()
                    except asyncio.QueueEmpty:
                        await asyncio.sleep(0.1)
                        try:
                            url, depth = queue.get_nowait()
                        except asyncio.QueueEmpty:
                            return

                    if url in self.visited or len(self.results) >= max_pages:
                        queue.task_done()
                        continue

                    if depth > max_depth:
                        queue.task_done()
                        continue

                    parsed = urlparse(url)
                    if parsed.netloc != base_domain:
                        queue.task_done()
                        continue

                    if self._is_disallowed(url):
                        queue.task_done()
                        continue

                    self.visited.add(url)
                    progress.update(
                        task,
                        advance=1,
                        description=f"[cyan]Crawling:[/cyan] {url[:65]}",
                    )

                    page = await self._fetch_page(url)
                    if page:
                        # If regex_match_only mode, skip pages with no matches
                        if self.regex_match_only and self.regex_engine.is_valid():
                            if not page.matched_patterns:
                                for link in page.links:
                                    if link not in self.visited:
                                        await queue.put((link, depth + 1))
                                queue.task_done()
                                await asyncio.sleep(random.uniform(*self.delay_range))
                                continue

                        self.results.append(page)
                        for link in page.links:
                            if link not in self.visited:
                                await queue.put((link, depth + 1))

                    queue.task_done()
                    await asyncio.sleep(random.uniform(*self.delay_range))

            workers = [asyncio.create_task(worker()) for _ in range(self.concurrency)]
            await queue.join()
            for w in workers:
                w.cancel()

    # ── Page Fetcher ──────────────────────────────────────────────────────────

    async def _fetch_page(self, url: str) -> Optional[ScrapedPage]:
        async with self._semaphore:
            headers = self._stealth_headers()
            try:
                t0 = time.monotonic()
                async with self._session.get(
                    url, headers=headers, allow_redirects=True
                ) as resp:
                    elapsed = (time.monotonic() - t0) * 1000
                    ctype = resp.headers.get("content-type", "")
                    if "text/html" not in ctype and "text/plain" not in ctype:
                        return None

                    html = await resp.text(errors="replace")
                    soup = BeautifulSoup(html, "html.parser")
                    resp_headers = dict(resp.headers)

                    page = self._parse_html(
                        url, html, soup, resp.status, ctype, elapsed, resp_headers
                    )

                    if self.use_playwright and self._needs_js_render(html):
                        page = await self._playwright_render(url, page)

                    return page

            except Exception as e:
                logger.debug(f"Failed {url}: {e}")
                return None

    def _needs_js_render(self, html: str) -> bool:
        soup = BeautifulSoup(html, "html.parser")
        text_len = len(soup.get_text(strip=True))
        script_count = len(soup.find_all("script"))
        return text_len < 500 and script_count > 3

    # ── HTML Parser & Recon Extractors ────────────────────────────────────────

    def _parse_html(
        self,
        url: str,
        html: str,
        soup: BeautifulSoup,
        status: int,
        ctype: str,
        elapsed: float,
        headers: Dict,
    ) -> ScrapedPage:
        base_domain = urlparse(url).netloc

        title_tag = soup.find("title")
        title = title_tag.get_text(strip=True) if title_tag else "No title"

        links, external_links = self._extract_links(soup, url, base_domain)
        tech = self._fingerprint(html, soup, headers)

        # Plain text for regex matching (tag-stripped)
        page_text = soup.get_text(separator=" ", strip=True)

        # ── Regex matching ───────────────────────────────────────────────────
        regex_matches: List[RegexMatch] = []
        matched_patterns: List[str] = []
        if self.regex_engine.is_valid():
            regex_matches, matched_patterns = self.regex_engine.match_page(
                page_text, html
            )

        return ScrapedPage(
            url=url,
            title=title,
            status_code=status,
            content_type=ctype,
            text_preview=page_text[:600],
            response_time_ms=round(elapsed, 1),
            links=links,
            external_links=external_links,
            emails=self._extract_emails(html),
            phones=self._extract_phones(html),
            forms=self._extract_forms(soup, url),
            scripts=[s.get("src", "") for s in soup.find_all("script") if s.get("src")],
            comments=self._extract_comments(html),
            meta=self._extract_meta(soup),
            social_links=self._extract_social(soup),
            subdomains=self._extract_subdomains(html, base_domain),
            api_endpoints=self._extract_api_endpoints(html),
            js_variables=self._extract_js_vars(html),
            tech=tech,
            regex_matches=regex_matches,
            matched_patterns=matched_patterns,
        )

    def _extract_emails(self, text: str) -> List[str]:
        found = RE_EMAIL.findall(text)
        filtered = [
            e for e in found if not e.endswith((".png", ".jpg", ".gif", ".css", ".js"))
        ]
        return list(dict.fromkeys(filtered))

    def _extract_phones(self, text: str) -> List[str]:
        found = RE_PHONE.findall(text)
        clean = [re.sub(r"\D", "", p) for p in found]
        valid = [p for p in clean if 10 <= len(p) <= 15]
        return list(dict.fromkeys(valid))

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        forms = []
        for form in soup.find_all("form"):
            inputs = []
            for inp in form.find_all(["input", "textarea", "select", "button"]):
                inputs.append(
                    {
                        "name": inp.get("name", ""),
                        "type": inp.get("type", "text"),
                        "id": inp.get("id", ""),
                        "placeholder": inp.get("placeholder", ""),
                        "required": inp.has_attr("required"),
                        "autocomplete": inp.get("autocomplete", ""),
                    }
                )
            forms.append(
                {
                    "action": urljoin(base_url, form.get("action", "")),
                    "method": form.get("method", "GET").upper(),
                    "enctype": form.get("enctype", ""),
                    "id": form.get("id", ""),
                    "inputs": inputs,
                    "input_count": len(inputs),
                    "has_password": any(i["type"] == "password" for i in inputs),
                    "has_file_upload": any(i["type"] == "file" for i in inputs),
                }
            )
        return forms

    def _extract_links(
        self, soup: BeautifulSoup, base_url: str, base_domain: str
    ) -> Tuple[List[str], List[str]]:
        internal, external = set(), set()
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            full = urljoin(base_url, href).split("#")[0]
            if not full.startswith(("http://", "https://")):
                continue
            if urlparse(full).netloc == base_domain:
                internal.add(full)
            else:
                external.add(full)
        return list(internal), list(external)

    def _extract_comments(self, html: str) -> List[str]:
        found = RE_COMMENT.findall(html)
        return [c.strip()[:300] for c in found if c.strip()][:30]

    def _extract_meta(self, soup: BeautifulSoup) -> Dict[str, str]:
        meta = {}
        for tag in soup.find_all("meta"):
            name = tag.get("name") or tag.get("property") or tag.get("http-equiv") or ""
            content = tag.get("content", "")
            if name and content:
                meta[name.lower()] = content[:200]
        return meta

    def _extract_social(self, soup: BeautifulSoup) -> List[str]:
        social = set()
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if any(pat in href for pat in SOCIAL_PATTERNS):
                social.add(href)
        return list(social)

    def _extract_subdomains(self, html: str, base_domain: str) -> List[str]:
        root = ".".join(base_domain.split(".")[-2:])
        pattern = re.compile(
            r"(?:https?://)?([a-zA-Z0-9\-]+\." + re.escape(root) + r")", re.IGNORECASE
        )
        found = pattern.findall(html)
        return list({s.lower() for s in found if s.lower() != base_domain})

    def _extract_api_endpoints(self, html: str) -> List[str]:
        found = RE_API.findall(html)
        return list(dict.fromkeys(found))[:40]

    def _extract_js_vars(self, html: str) -> List[str]:
        found = RE_JS_VAR.findall(html)
        interesting = [
            f"{name}={val}"
            for name, val in found
            if any(
                kw in name.lower()
                for kw in [
                    "key",
                    "token",
                    "secret",
                    "api",
                    "auth",
                    "pass",
                    "url",
                    "endpoint",
                    "config",
                ]
            )
        ]
        return interesting[:20]

    # ── Tech Fingerprinting ───────────────────────────────────────────────────

    def _fingerprint(
        self, html: str, soup: BeautifulSoup, headers: Dict
    ) -> TechFingerprint:
        lower_headers = {k.lower(): v for k, v in headers.items()}
        tech = TechFingerprint()

        tech.server = lower_headers.get("server", "")
        tech.powered_by = lower_headers.get("x-powered-by", "")

        for cms, sigs in CMS_SIGNATURES.items():
            if any(sig in html for sig in sigs):
                tech.cms = cms
                tech.frameworks.append(cms)

        for waf, sigs in WAF_SIGNATURES.items():
            if any(s in lower_headers for s in sigs) or any(
                s in html.lower() for s in sigs
            ):
                tech.waf = waf
                break

        for cdn, sigs in CDN_SIGNATURES.items():
            if any(s in lower_headers for s in sigs):
                tech.cdn = cdn
                break

        tech.cookies = [
            c.split("=")[0].strip()
            for c in lower_headers.get("set-cookie", "").split(";")
            if "=" in c
        ]

        for h in SECURITY_HEADERS:
            if h in lower_headers:
                tech.security_headers[h] = lower_headers[h][:80]
            else:
                tech.missing_security_headers.append(h)

        return tech

    # ── Playwright JS Rendering ───────────────────────────────────────────────

    async def _start_playwright(self):
        if not PLAYWRIGHT_AVAILABLE:
            console.print(
                "[yellow]Playwright not installed. Skipping JS rendering.[/yellow]"
            )
            return
        pw = await async_playwright().start()
        self._playwright_browser = await pw.chromium.launch(headless=True)

    async def _playwright_render(self, url: str, base_page: ScrapedPage) -> ScrapedPage:
        if not self._playwright_browser:
            return base_page
        async with self._playwright_sem:
            try:
                context = await self._playwright_browser.new_context(
                    user_agent=random.choice(USER_AGENTS),
                    ignore_https_errors=not self.verify_ssl,
                )
                page: PlaywrightPage = await context.new_page()
                await page.goto(url, wait_until="networkidle", timeout=20000)
                html = await page.content()
                await context.close()

                soup = BeautifulSoup(html, "html.parser")
                rendered = self._parse_html(
                    url,
                    html,
                    soup,
                    base_page.status_code,
                    base_page.content_type,
                    base_page.response_time_ms,
                    {},
                )
                rendered.rendered = True
                return rendered
            except Exception as e:
                logger.debug(f"Playwright failed for {url}: {e}")
                return base_page

    # ── Stealth Headers ───────────────────────────────────────────────────────

    def _stealth_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": random.choice(ACCEPT_HEADERS),
            "Accept-Language": random.choice(
                ["en-US,en;q=0.9", "en-GB,en;q=0.8", "en;q=0.7"]
            ),
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": random.choice(["1", "0"]),
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": random.choice(["none", "same-origin"]),
            "Cache-Control": random.choice(["max-age=0", "no-cache"]),
        }

    # ── Robots.txt ────────────────────────────────────────────────────────────

    async def _fetch_robots(self, start_url: str):
        parsed = urlparse(start_url)
        robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
        try:
            async with self._session.get(
                robots_url, timeout=ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    in_block = False
                    for line in text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("user-agent:"):
                            agent = line.split(":", 1)[1].strip()
                            in_block = agent in ("*", "CREEPER")
                        elif in_block and line.lower().startswith("disallow:"):
                            path = line.split(":", 1)[1].strip()
                            if path:
                                self.disallowed.add(
                                    f"{parsed.scheme}://{parsed.netloc}{path}"
                                )
        except Exception:
            pass

    def _is_disallowed(self, url: str) -> bool:
        return any(url.startswith(d) for d in self.disallowed)

    # ── Report Builder ────────────────────────────────────────────────────────

    def _build_report(self, start_url: str) -> Dict:
        all_emails: Set[str] = set()
        all_phones: Set[str] = set()
        all_forms: List[Dict] = []
        all_comments: List[str] = []
        all_subdomains: Set[str] = set()
        all_api_endpoints: Set[str] = set()
        all_js_vars: Set[str] = set()
        all_social: Set[str] = set()
        all_external: Set[str] = set()
        pages_by_status: Dict[int, int] = {}
        tech_summary: Dict = {}
        response_times: List[float] = []

        # ── Regex match aggregation ──────────────────────────────────────────
        regex_hit_urls: List[Dict] = []  # [{url, title, matched_patterns, matches}]
        pattern_hit_count: Dict[str, int] = {}

        for page in self.results:
            all_emails.update(page.emails)
            all_phones.update(page.phones)
            all_forms.extend(page.forms)
            all_comments.extend(page.comments)
            all_subdomains.update(page.subdomains)
            all_api_endpoints.update(page.api_endpoints)
            all_js_vars.update(page.js_variables)
            all_social.update(page.social_links)
            all_external.update(page.external_links)
            response_times.append(page.response_time_ms)
            pages_by_status[page.status_code] = (
                pages_by_status.get(page.status_code, 0) + 1
            )

            # Regex hits
            if page.matched_patterns:
                regex_hit_urls.append(
                    {
                        "url": page.url,
                        "title": page.title,
                        "matched_patterns": page.matched_patterns,
                        "matches": [
                            {
                                "pattern": m.pattern,
                                "match_text": m.match_text,
                                "match_count": m.match_count,
                                "context": m.context,
                            }
                            for m in page.regex_matches
                        ],
                    }
                )
                for pat in page.matched_patterns:
                    pattern_hit_count[pat] = pattern_hit_count.get(pat, 0) + 1

            # Tech fingerprint merge
            t = page.tech
            if t.cms and not tech_summary.get("cms"):
                tech_summary["cms"] = t.cms
            if t.waf and not tech_summary.get("waf"):
                tech_summary["waf"] = t.waf
            if t.cdn and not tech_summary.get("cdn"):
                tech_summary["cdn"] = t.cdn
            if t.server and not tech_summary.get("server"):
                tech_summary["server"] = t.server
            if t.powered_by and not tech_summary.get("powered_by"):
                tech_summary["powered_by"] = t.powered_by
            if t.frameworks:
                existing = tech_summary.get("frameworks", set())
                if isinstance(existing, set):
                    existing.update(t.frameworks)
                tech_summary["frameworks"] = existing
            if t.missing_security_headers:
                tech_summary.setdefault("missing_security_headers", set()).update(
                    t.missing_security_headers
                )

        if "frameworks" in tech_summary and isinstance(tech_summary["frameworks"], set):
            tech_summary["frameworks"] = sorted(tech_summary["frameworks"])
        if "missing_security_headers" in tech_summary and isinstance(
            tech_summary["missing_security_headers"], set
        ):
            tech_summary["missing_security_headers"] = sorted(
                tech_summary["missing_security_headers"]
            )

        avg_rt = (
            round(sum(response_times) / len(response_times), 1) if response_times else 0
        )

        return {
            "target": start_url,
            "scraped_at": datetime.utcnow().isoformat() + "Z",
            "total_pages": len(self.results),
            "avg_response_time_ms": avg_rt,
            # ── Regex results (the new hero feature) ──
            "regex_patterns_used": self.regex_engine.raw_patterns,
            "regex_pattern_errors": self.regex_engine.errors,
            "regex_matched_urls": regex_hit_urls,  # URLs where ≥1 pattern matched
            "regex_total_hits": len(regex_hit_urls),
            "regex_pattern_hit_count": pattern_hit_count,  # how many pages each pattern hit
            # ── Standard OSINT data ──
            "emails": sorted(all_emails),
            "phones": sorted(all_phones),
            "forms": all_forms,
            "comments": all_comments,
            "subdomains": sorted(all_subdomains),
            "api_endpoints": sorted(all_api_endpoints),
            "js_sensitive_vars": sorted(all_js_vars),
            "social_links": sorted(all_social),
            "external_links": sorted(all_external)[:200],
            "pages_by_status": pages_by_status,
            "tech": tech_summary,
            "pages": [asdict(p) for p in self.results],
        }

    # ── Exporters ─────────────────────────────────────────────────────────────

    def _export(self, report: Dict, output_dir: str, formats: List[str]):
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        domain = urlparse(report["target"]).netloc.replace(".", "_")
        stem = f"CREEPER_{domain}_{ts}"

        for fmt in formats:
            fmt = fmt.lower().strip()
            if fmt == "json":
                path = out / f"{stem}.json"
                path.write_text(
                    json.dumps(report, indent=2, default=str), encoding="utf-8"
                )
                console.print(f"[green]✓ JSON exported:[/green] {path}")

            elif fmt == "csv":
                path = out / f"{stem}_pages.csv"
                if report["pages"]:
                    keys = [
                        "url",
                        "title",
                        "status_code",
                        "response_time_ms",
                        "emails",
                        "phones",
                        "api_endpoints",
                        "matched_patterns",
                    ]
                    with open(path, "w", newline="", encoding="utf-8") as f:
                        writer = csv.DictWriter(
                            f, fieldnames=keys, extrasaction="ignore"
                        )
                        writer.writeheader()
                        for p in report["pages"]:
                            row = {
                                k: (
                                    json.dumps(p[k])
                                    if isinstance(p.get(k), list)
                                    else p.get(k, "")
                                )
                                for k in keys
                            }
                            writer.writerow(row)
                # Also export regex matches as separate CSV
                if report["regex_matched_urls"]:
                    rx_path = out / f"{stem}_regex_matches.csv"
                    with open(rx_path, "w", newline="", encoding="utf-8") as f:
                        writer = csv.DictWriter(
                            f,
                            fieldnames=[
                                "url",
                                "title",
                                "matched_patterns",
                                "match_details",
                            ],
                        )
                        writer.writeheader()
                        for hit in report["regex_matched_urls"]:
                            writer.writerow(
                                {
                                    "url": hit["url"],
                                    "title": hit["title"],
                                    "matched_patterns": "|".join(
                                        hit["matched_patterns"]
                                    ),
                                    "match_details": json.dumps(hit["matches"]),
                                }
                            )
                    console.print(f"[green]✓ Regex matches CSV:[/green] {rx_path}")
                console.print(f"[green]✓ CSV exported:[/green] {path}")

            elif fmt == "sqlite":
                path = out / f"{stem}.db"
                self._export_sqlite(report, path)
                console.print(f"[green]✓ SQLite exported:[/green] {path}")

    def _export_sqlite(self, report: Dict, db_path: Path):
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS pages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT, title TEXT, status_code INTEGER,
                response_time_ms REAL, rendered INTEGER,
                emails TEXT, phones TEXT, forms TEXT,
                api_endpoints TEXT, js_variables TEXT,
                comments TEXT, subdomains TEXT,
                matched_patterns TEXT,
                cms TEXT, waf TEXT, cdn TEXT, server TEXT,
                missing_security_headers TEXT
            )
        """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS regex_matches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT, title TEXT,
                pattern TEXT, match_text TEXT,
                match_count INTEGER, context TEXT
            )
        """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY, value TEXT
            )
        """
        )

        meta_rows = [
            ("target", report["target"]),
            ("scraped_at", report["scraped_at"]),
            ("total_pages", str(report["total_pages"])),
            ("avg_response_time_ms", str(report["avg_response_time_ms"])),
            ("regex_patterns", json.dumps(report["regex_patterns_used"])),
            ("regex_total_hits", str(report["regex_total_hits"])),
            ("emails", json.dumps(report["emails"])),
            ("phones", json.dumps(report["phones"])),
            ("subdomains", json.dumps(report["subdomains"])),
            ("api_endpoints", json.dumps(report["api_endpoints"])),
        ]
        cur.executemany("INSERT OR REPLACE INTO meta VALUES (?, ?)", meta_rows)

        for p in report["pages"]:
            tech = p.get("tech", {})
            cur.execute(
                """
                INSERT INTO pages
                (url, title, status_code, response_time_ms, rendered,
                 emails, phones, forms, api_endpoints, js_variables,
                 comments, subdomains, matched_patterns,
                 cms, waf, cdn, server, missing_security_headers)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
                (
                    p["url"],
                    p["title"],
                    p["status_code"],
                    p["response_time_ms"],
                    int(p["rendered"]),
                    json.dumps(p["emails"]),
                    json.dumps(p["phones"]),
                    json.dumps(p["forms"]),
                    json.dumps(p["api_endpoints"]),
                    json.dumps(p["js_variables"]),
                    json.dumps(p["comments"]),
                    json.dumps(p["subdomains"]),
                    json.dumps(p.get("matched_patterns", [])),
                    tech.get("cms", ""),
                    tech.get("waf", ""),
                    tech.get("cdn", ""),
                    tech.get("server", ""),
                    json.dumps(tech.get("missing_security_headers", [])),
                ),
            )

        # Regex matches table
        for hit in report["regex_matched_urls"]:
            for m in hit["matches"]:
                cur.execute(
                    """
                    INSERT INTO regex_matches (url, title, pattern, match_text, match_count, context)
                    VALUES (?,?,?,?,?,?)
                """,
                    (
                        hit["url"],
                        hit["title"],
                        m["pattern"],
                        m["match_text"],
                        m["match_count"],
                        m["context"],
                    ),
                )

        conn.commit()
        conn.close()


# ─── Rich Display ──────────────────────────────────────────────────────────────


def format_scraper(parsed: dict) -> None:
    """Render a rich OSINT report to the terminal."""

    tech = parsed.get("tech", {})
    regex_hits = parsed.get("regex_matched_urls", [])

    # ── Header ──
    header = Text()
    header.append("  Target:            ", style="dim")
    header.append(f"{parsed.get('target', '?')}\n", style="bold cyan")
    header.append("  Scraped at:        ", style="dim")
    header.append(f"{parsed.get('scraped_at', '?')}\n", style="white")
    header.append("  Pages crawled:     ", style="dim")
    header.append(f"{parsed.get('total_pages', 0)}\n", style="bold green")
    header.append("  Avg response time: ", style="dim")
    header.append(f"{parsed.get('avg_response_time_ms', 0)} ms\n", style="white")
    header.append("  Regex patterns:    ", style="dim")
    header.append(
        f"{len(parsed.get('regex_patterns_used', []))}\n", style="bold magenta"
    )
    header.append("  Regex hits (URLs): ", style="dim")
    header.append(f"{parsed.get('regex_total_hits', 0)}\n", style="bold red")
    header.append("  Emails found:      ", style="dim")
    header.append(f"{len(parsed.get('emails', []))}\n", style="bold yellow")
    header.append("  Phones found:      ", style="dim")
    header.append(f"{len(parsed.get('phones', []))}\n", style="bold yellow")
    header.append("  Forms found:       ", style="dim")
    header.append(f"{len(parsed.get('forms', []))}\n", style="bold magenta")
    header.append("  API endpoints:     ", style="dim")
    header.append(f"{len(parsed.get('api_endpoints', []))}\n", style="bold red")
    header.append("  Subdomains:        ", style="dim")
    header.append(f"{len(parsed.get('subdomains', []))}", style="bold blue")

    console.print(
        Panel(
            header,
            title="[bold cyan]🕷️  CREEPER OSINT Scraper Report[/bold cyan]",
            border_style="cyan",
            box=box.ROUNDED,
        )
    )

    # ── Regex Matches (the new hero section) ──────────────────────────────────
    if regex_hits:
        console.print(
            f"\n[bold red]🎯 Regex Pattern Matches — {len(regex_hits)} URL(s)[/bold red]"
        )

        pat_counts = parsed.get("regex_pattern_hit_count", {})
        if pat_counts:
            console.print("  [dim]Pattern hit summary:[/dim]")
            for pat, cnt in sorted(pat_counts.items(), key=lambda x: -x[1]):
                console.print(
                    f"    [magenta]{pat}[/magenta]  →  [yellow]{cnt} page(s)[/yellow]"
                )

        console.print()
        for i, hit in enumerate(regex_hits, 1):
            pats = ", ".join(f"[magenta]{p}[/magenta]" for p in hit["matched_patterns"])
            console.print(f"  [dim]{i:3}.[/dim] [cyan]{hit['url']}[/cyan]")
            console.print(f"        [dim]Title:[/dim] {hit['title']}")
            console.print(f"        [dim]Patterns:[/dim] {pats}")
            for m in hit["matches"][:3]:
                console.print(
                    f"        [dim]Match:[/dim] [green]{m['match_text'][:80]}[/green]  "
                    f"[dim]({m['match_count']}×)[/dim]"
                )
            console.print()

    elif parsed.get("regex_patterns_used"):
        console.print(f"\n[dim]No pages matched the supplied regex patterns.[/dim]")

    # ── Tech Fingerprint ──
    if tech:
        console.print("\n[bold white]🔍 Technology Fingerprint[/bold white]")
        fp_table = Table(show_header=False, box=box.SIMPLE, padding=(0, 1))
        rows = [
            ("Server", tech.get("server", "—"), "cyan"),
            ("Powered By", tech.get("powered_by", "—"), "cyan"),
            ("CMS", tech.get("cms", "—"), "green"),
            ("WAF", tech.get("waf", "—"), "red"),
            ("CDN", tech.get("cdn", "—"), "blue"),
            ("Frameworks", ", ".join(tech.get("frameworks", [])) or "—", "yellow"),
        ]
        for label, val, color in rows:
            fp_table.add_row(f"  [dim]{label}[/dim]", f"[{color}]{val}[/{color}]")
        console.print(fp_table)

        missing = tech.get("missing_security_headers", [])
        if missing:
            console.print(
                f"  [red]⚠ Missing security headers:[/red] {', '.join(missing)}"
            )

    # ── Emails ──
    emails = parsed.get("emails", [])
    if emails:
        console.print("\n[bold yellow]📧 Emails Found[/bold yellow]")
        for e in emails[:50]:
            console.print(f"  [cyan]✉[/cyan]  {e}")
        if len(emails) > 50:
            console.print(f"  [dim]... and {len(emails)-50} more[/dim]")

    # ── Phones ──
    phones = parsed.get("phones", [])
    if phones:
        console.print("\n[bold yellow]📞 Phone Numbers Found[/bold yellow]")
        for p in phones[:20]:
            console.print(f"  [cyan]☏[/cyan]  {p}")

    # ── Subdomains ──
    subdomains = parsed.get("subdomains", [])
    if subdomains:
        console.print("\n[bold blue]🌐 Subdomains Discovered[/bold blue]")
        for s in subdomains[:30]:
            console.print(f"  [dim]→[/dim] {s}")

    # ── API Endpoints ──
    apis = parsed.get("api_endpoints", [])
    if apis:
        console.print("\n[bold red]🔗 API Endpoints Detected[/bold red]")
        for ep in apis[:30]:
            console.print(f"  [red]›[/red] {ep}")

    # ── Sensitive JS Variables ──
    js_vars = parsed.get("js_sensitive_vars", [])
    if js_vars:
        console.print("\n[bold red]⚠  Sensitive JS Variables[/bold red]")
        for v in js_vars[:20]:
            console.print(f"  [red]![/red] {v[:120]}")

    # ── Forms ──
    forms = parsed.get("forms", [])
    if forms:
        console.print("\n[bold magenta]📝 Forms — Attack Surface[/bold magenta]")
        for i, form in enumerate(forms[:15], 1):
            flags = []
            if form.get("has_password"):
                flags.append("[red]PASSWORD[/red]")
            if form.get("has_file_upload"):
                flags.append("[yellow]FILE UPLOAD[/yellow]")
            flag_str = " ".join(flags)
            console.print(
                f"\n  [dim]{i}.[/dim] [yellow]{form['method']}[/yellow] "
                f"→ [cyan]{form['action'][:70]}[/cyan] {flag_str}"
            )
            names = [inp["name"] for inp in form["inputs"] if inp["name"]]
            if names:
                console.print(f"     [dim]Fields:[/dim] {', '.join(names[:8])}")

    # ── HTML Comments ──
    comments = parsed.get("comments", [])
    if comments:
        console.print("\n[bold green]💬 HTML Comments[/bold green]")
        for c in comments[:10]:
            console.print(f"  [dim]»[/dim] {c[:120]}")

    # ── Social Links ──
    social = parsed.get("social_links", [])
    if social:
        console.print("\n[bold cyan]🔗 Social Profiles[/bold cyan]")
        for s in social[:20]:
            console.print(f"  [dim]↗[/dim] {s}")

    # ── Status Codes ──
    pages_by_status = parsed.get("pages_by_status", {})
    if pages_by_status:
        console.print("\n[bold blue]📄 Pages by Status[/bold blue]")
        for status, count in sorted(pages_by_status.items()):
            color = (
                "green" if status == 200 else "yellow" if 300 <= status < 400 else "red"
            )
            console.print(f"  [{color}]{status}[/{color}]  {count} page(s)")

    console.print()
