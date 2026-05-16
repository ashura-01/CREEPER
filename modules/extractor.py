"""
modules/extractor.py
HTML parsing and recon extraction — all the "what did we find on this page?" logic.
Depends only on models.py and constants.py.
"""

from __future__ import annotations

import re
import logging
from typing import Dict, List, Set, Tuple
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from .models import TechFingerprint
from .constants import (
    CMS_SIGNATURES,
    WAF_SIGNATURES,
    CDN_SIGNATURES,
    SECURITY_HEADERS,
    JS_SECRET_KEYWORDS,
    RE_EMAIL,
    RE_PHONE,
    RE_COMMENT,
    RE_API,
    RE_JS_VAR,
    RE_HIDDEN_INPUT,
    RE_SOURCEMAP,
    RE_HARDCODED_SECRET,
    SKIP_EXTENSIONS,
)

logger = logging.getLogger("CREEPER.extractor")

# File-extension endings that appear in fake "emails" like foo@2x.png
_EMAIL_SKIP_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg",
                    ".css", ".js", ".woff", ".ttf", ".eot", ".ico")


# ── Email extraction ──────────────────────────────────────────────────────────

def extract_emails(html: str) -> List[str]:
    found = RE_EMAIL.findall(html)
    cleaned = [
        e for e in found
        if not any(e.lower().endswith(ext) for ext in _EMAIL_SKIP_EXTS)
        and "example" not in e.lower()
        and len(e) < 120
    ]
    return list(dict.fromkeys(cleaned))


# ── Phone extraction ──────────────────────────────────────────────────────────

def extract_phones(html: str) -> List[str]:
    found = RE_PHONE.findall(html)
    clean = [re.sub(r"\D", "", p) for p in found]
    valid = [p for p in clean if 7 <= len(p) <= 15]
    return list(dict.fromkeys(valid))


# ── Form extraction ───────────────────────────────────────────────────────────

def extract_forms(soup: BeautifulSoup, base_url: str) -> List[Dict]:
    forms = []
    for form in soup.find_all("form"):
        inputs = []
        for inp in form.find_all(["input", "textarea", "select", "button"]):
            inp_type = inp.get("type", "text").lower()
            inputs.append({
                "name":         inp.get("name", ""),
                "type":         inp_type,
                "id":           inp.get("id", ""),
                "placeholder":  inp.get("placeholder", ""),
                "required":     inp.has_attr("required"),
                "autocomplete": inp.get("autocomplete", ""),
                # Capture hidden values — often tokens/IDs valuable for bug hunting
                "value": inp.get("value", "")[:120] if inp_type == "hidden" else "",
            })

        action = form.get("action", "")
        has_csrf = any(
            "csrf" in (i.get("name", "") + i.get("id", "")).lower()
            or "token" in (i.get("name", "") + i.get("id", "")).lower()
            for i in inputs
        )
        forms.append({
            "action":          urljoin(base_url, action) if action else base_url,
            "method":          form.get("method", "GET").upper(),
            "enctype":         form.get("enctype", ""),
            "id":              form.get("id", ""),
            "name":            form.get("name", ""),
            "inputs":          inputs,
            "input_count":     len(inputs),
            "has_password":    any(i["type"] == "password"  for i in inputs),
            "has_file_upload": any(i["type"] == "file"      for i in inputs),
            "has_hidden":      any(i["type"] == "hidden"    for i in inputs),
            "has_csrf_token":  has_csrf,
        })
    return forms


# ── Link extraction ───────────────────────────────────────────────────────────

def extract_links(
    soup: BeautifulSoup, base_url: str, base_domain: str
) -> Tuple[List[str], List[str]]:
    """
    base_domain should be the bare domain WITHOUT www. prefix.
    We accept both bare and www. variants as internal links so that
    www-redirects don't orphan the entire link graph.
    """
    bare = base_domain.lower().removeprefix("www.")
    accepted = {bare, f"www.{bare}"}

    internal: Set[str] = set()
    external: Set[str] = set()

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
            continue

        full = urljoin(base_url, href).split("#")[0].rstrip("?&")
        if not full.startswith(("http://", "https://")):
            continue

        # Skip binary/media extensions — no HTML to parse there
        path_lower = urlparse(full).path.lower()
        if any(path_lower.endswith(ext) for ext in SKIP_EXTENSIONS):
            continue

        link_domain = urlparse(full).netloc.lower()
        if link_domain in accepted:
            internal.add(full)
        else:
            external.add(full)

    return list(internal)[:600], list(external)[:200]


# ── Comment extraction ────────────────────────────────────────────────────────

def extract_comments(html: str) -> List[str]:
    found = RE_COMMENT.findall(html)
    return [c.strip()[:300] for c in found if c.strip()][:25]


# ── Meta-tag extraction ───────────────────────────────────────────────────────

def extract_meta(soup: BeautifulSoup) -> Dict[str, str]:
    meta: Dict[str, str] = {}
    for tag in soup.find_all("meta"):
        name    = tag.get("name") or tag.get("property") or tag.get("http-equiv") or ""
        content = tag.get("content", "")
        if name and content:
            meta[name.lower()] = content[:200]
    return meta


# ── Subdomain extraction ──────────────────────────────────────────────────────

def extract_subdomains(html: str, base_domain: str) -> List[str]:
    bare = base_domain.lower().removeprefix("www.")
    root = ".".join(bare.split(".")[-2:])
    pattern = re.compile(
        r'(?:https?://)?([a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)*\.' + re.escape(root) + r')',
        re.IGNORECASE,
    )
    found = pattern.findall(html)
    # exclude both bare and www variants of the base domain itself
    exclude = {bare, f"www.{bare}"}
    return list({s.lower() for s in found if s.lower() not in exclude})[:60]


# ── API endpoint extraction ───────────────────────────────────────────────────

def extract_api_endpoints(html: str, base_url: str = "") -> List[str]:
    primary = RE_API.findall(html)
    # Second pass: bare path strings in script blocks
    extra   = re.findall(
        r'''["'](/(?:api|v\d+|graphql|rest|gql|rpc|endpoint|webhook)[^"'\s<>]{0,100})["']''',
        html,
    )
    # Third pass: fetch/axios/XHR calls with any path (broader than api/* only)
    fetch_paths = re.findall(
        r'''(?:fetch|axios\.(?:get|post|put|patch|delete|request)|\$\.(?:ajax|get|post))\s*\([\s\n]*["'`]([^"'`\s]{3,120})["'`]''',
        html,
    )
    # Fourth pass: route definitions (common in React/Vue/Next/Express)
    route_paths = re.findall(
        r'''(?:path|route|href|to)\s*[=:]\s*["'`](/[a-zA-Z0-9/_\-.:?=&%]{3,100})["'`]''',
        html,
    )
    # Fifth pass: XMLHttpRequest .open() calls
    xhr_paths = re.findall(
        r'''\.open\s*\(\s*["'`](?:GET|POST|PUT|PATCH|DELETE)["'`]\s*,\s*["'`]([^"'`\s]{3,120})["'`]''',
        html,
        re.IGNORECASE,
    )
    combined = list(dict.fromkeys(primary + extra + fetch_paths + route_paths + xhr_paths))
    # Filter out obvious non-endpoints
    STATIC_EXTS = (".png",".jpg",".jpeg",".gif",".svg",".css",".ico",".woff",
                    ".woff2",".ttf",".eot",".otf",".map",".mp4",".webp",".pdf")
    combined = [
        e for e in combined
        if not any(e.split("?")[0].endswith(ext) for ext in STATIC_EXTS)
        and not e.startswith("//")
        and len(e) > 2
        # exclude query-string-only version patterns like ?ver=8.4.5
        and not re.match(r'^/v\d+/[a-z].*\.(css|js)(\?|$)', e, re.IGNORECASE)
    ]

    # Resolve bare paths to absolute URLs using the page origin
    if base_url:
        parsed  = urlparse(base_url)
        origin  = f"{parsed.scheme}://{parsed.netloc}"
        resolved = []
        for ep in combined:
            if ep.startswith("/") and not ep.startswith("//"):
                resolved.append(origin + ep)
            elif ep.startswith(("http://", "https://")):
                resolved.append(ep)
            else:
                resolved.append(ep)
        return list(dict.fromkeys(resolved))[:80]

    return combined[:80]




# -- URL parameter extraction --------------------------------------------------

_RE_JS_URL_PARAMS = re.compile(
    r'["\'"`][^"\'"`]*[?]([a-zA-Z0-9_\-]{2,40}=[^&"\'"`\s]{0,80}'
    r'(?:&[a-zA-Z0-9_\-]{2,40}=[^&"\'"`\s]{0,80})*)["\'"`]'
)


def extract_parameters(soup: BeautifulSoup, page_url: str, html: str) -> List[Dict]:
    from urllib.parse import urlparse as _up, parse_qs, urljoin

    seen: Dict[str, Dict] = {}

    def add(name: str, value: str, url: str, method: str = "GET"):
        if not name or len(name) > 80 or name.startswith("_"):
            return
        key = f"{method}:{name}"
        if key not in seen:
            seen[key] = {"name": name, "value": value[:200], "url": url, "method": method}

    # Current page URL params
    try:
        for k, vs in parse_qs(_up(page_url).query).items():
            add(k, vs[0] if vs else "", page_url, "GET")
    except Exception:
        pass

    # All anchor href params
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if "?" not in href:
            continue
        try:
            full = urljoin(page_url, href)
            for k, vs in parse_qs(_up(full).query).items():
                add(k, vs[0] if vs else "", full, "GET")
        except Exception:
            pass

    # Form inputs
    for form in soup.find_all("form"):
        action = form.get("action", "")
        try:
            action_url = urljoin(page_url, action) if action else page_url
        except Exception:
            action_url = page_url
        method = form.get("method", "GET").upper()
        for inp in form.find_all(["input", "textarea", "select"]):
            iname = inp.get("name", "")
            itype = inp.get("type", "text").lower()
            ival  = inp.get("value", "") or inp.get("placeholder", "")
            if iname and itype not in ("hidden", "submit", "button", "image", "reset"):
                add(iname, ival, action_url, method)

    # JS string URL params
    for m in _RE_JS_URL_PARAMS.finditer(html):
        qs_str = m.group(1)
        try:
            for k, vs in parse_qs(qs_str).items():
                add(k, vs[0] if vs else "", page_url, "GET")
        except Exception:
            pass

    return list(seen.values())[:200]

# ── JS variable / secret extraction ──────────────────────────────────────────

def extract_js_vars(html: str) -> List[str]:
    results: List[str] = []

    # Named variables with security-relevant names
    for name, val in RE_JS_VAR.findall(html):
        if any(kw in name.lower() for kw in JS_SECRET_KEYWORDS):
            if len(val) >= 8 and val not in ("undefined", "null", "false", "true", ""):
                results.append(f"{name}={val[:120]}")

    # Hardcoded cloud/service API keys
    for m in RE_HARDCODED_SECRET.finditer(html):
        results.append(f"[SECRET] {m.group(0)[:80]}")

    # Source-map references
    for sm in RE_SOURCEMAP.findall(html):
        results.append(f"[SOURCEMAP] {sm}")

    return list(dict.fromkeys(results))[:30]


# ── Tech fingerprinting ───────────────────────────────────────────────────────

def fingerprint_tech(html: str, soup: BeautifulSoup, headers: Dict) -> TechFingerprint:
    lower_h = {k.lower(): v for k, v in headers.items()}
    tech    = TechFingerprint()

    tech.server     = lower_h.get("server", "")
    tech.powered_by = lower_h.get("x-powered-by", "")

    for cms, sigs in CMS_SIGNATURES.items():
        if any(sig in html for sig in sigs):
            tech.cms = cms
            if cms not in tech.frameworks:
                tech.frameworks.append(cms)

    for waf, sigs in WAF_SIGNATURES.items():
        if any(s in lower_h for s in sigs) or any(s in html.lower() for s in sigs):
            tech.waf = waf
            break

    for cdn, sigs in CDN_SIGNATURES.items():
        if any(s in lower_h for s in sigs):
            tech.cdn = cdn
            break

    # Cookie names from Set-Cookie header
    set_cookie = lower_h.get("set-cookie", "")
    tech.cookies = [
        c.split("=")[0].strip()
        for c in set_cookie.split(";")
        if "=" in c
    ]

    for h in SECURITY_HEADERS:
        if h in lower_h:
            tech.security_headers[h] = lower_h[h][:100]
        else:
            tech.missing_security_headers.append(h)

    return tech


# ── JS-render detection heuristic ────────────────────────────────────────────

def needs_js_render(html: str) -> bool:
    """True if the page seems SPA-heavy and likely needs Playwright rendering."""
    soup         = BeautifulSoup(html, "html.parser")
    text_len     = len(soup.get_text(strip=True))
    script_count = len(soup.find_all("script"))
    return text_len < 400 and script_count > 3